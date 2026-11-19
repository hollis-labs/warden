package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/hollis-labs/libs/core/store"

	"github.com/hollis-labs/warden/internal/approval"
	"github.com/hollis-labs/warden/internal/policy"
	"github.com/hollis-labs/warden/internal/scopes"
)

// Request is a credential request and where it stands.
type Request struct {
	ID            string            `json:"id"`
	Action        string            `json:"action"`
	Principal     string            `json:"principal"`
	PrincipalKind string            `json:"principal_kind"`
	Requester     string            `json:"requester,omitempty"`
	Audience      string            `json:"audience,omitempty"`
	Scopes        []string          `json:"scopes,omitempty"`
	TTLSeconds    int64             `json:"ttl_seconds,omitempty"`
	Constraints   map[string]any    `json:"constraints,omitempty"`
	Purpose       string            `json:"purpose,omitempty"`
	Evidence      map[string]string `json:"evidence,omitempty"`
	Tier          string            `json:"tier"`
	Rule          string            `json:"rule,omitempty"`
	Status        string            `json:"status"`
	ApprovalID    string            `json:"approval_id,omitempty"`
	DecidedBy     string            `json:"decided_by,omitempty"`
	GrantID       string            `json:"grant_id,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
	digest        string
}

// RequestInput is what a caller files.
type RequestInput struct {
	Principal   string            `json:"principal,omitempty"` // default: the caller
	Audience    string            `json:"audience"`
	Scopes      []string          `json:"scopes"`
	TTLSeconds  int64             `json:"ttl_seconds,omitempty"` // grant lifetime; default 30 days
	Constraints map[string]any    `json:"constraints,omitempty"`
	Purpose     string            `json:"purpose,omitempty"`
	Evidence    map[string]string `json:"evidence,omitempty"`
}

const reqCols = `id, action, principal, principal_kind, requester, audience, scopes, ttl_seconds, constraints, purpose, evidence,
	tier, rule, status, approval_id, digest, decided_by, grant_id, created_at, updated_at, expires_at`

func scanRequest(sc interface{ Scan(...any) error }) (Request, error) {
	var r Request
	var scs, cons, ev, created, updated, expires string
	err := sc.Scan(&r.ID, &r.Action, &r.Principal, &r.PrincipalKind, &r.Requester, &r.Audience, &scs, &r.TTLSeconds, &cons, &r.Purpose,
		&ev, &r.Tier, &r.Rule, &r.Status, &r.ApprovalID, &r.digest, &r.DecidedBy, &r.GrantID, &created, &updated, &expires)
	if err != nil {
		return Request{}, err
	}
	r.Scopes = strings.Fields(scs)
	_ = json.Unmarshal([]byte(cons), &r.Constraints)
	_ = json.Unmarshal([]byte(ev), &r.Evidence)
	r.CreatedAt, r.UpdatedAt, r.ExpiresAt = parseTS(created), parseTS(updated), parseTS(expires)
	return r, nil
}

func (s *Service) loadRequest(ctx context.Context, q store.Querier, id string) (Request, error) {
	r, err := scanRequest(q.QueryRowContext(ctx, `SELECT `+reqCols+` FROM requests WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	return r, err
}

func (s *Service) insertRequest(ctx context.Context, tx store.Tx, r *Request) error {
	now := s.now()
	r.CreatedAt, r.UpdatedAt = now, now
	if r.ExpiresAt.IsZero() {
		r.ExpiresAt = now.Add(s.cfg.RequestTTL)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO requests (`+reqCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Action, r.Principal, r.PrincipalKind, r.Requester, r.Audience, strings.Join(r.Scopes, " "), r.TTLSeconds,
		mustJSON(r.Constraints), r.Purpose, mustJSON(r.Evidence), r.Tier, r.Rule, r.Status, r.ApprovalID, r.digest, r.DecidedBy,
		r.GrantID, ts(r.CreatedAt), ts(r.UpdatedAt), ts(r.ExpiresAt))
	if err != nil {
		return err
	}
	return s.audit(ctx, tx, firstNonEmpty(r.Requester, r.Principal), "request.create", r.Principal,
		map[string]any{"request": r.ID, "action": r.Action, "audience": r.Audience, "scopes": r.Scopes, "tier": r.Tier, "rule": r.Rule, "status": r.Status})
}

// approvalRef is the request as Gatecrasher sees it, and as the digest covers it. An enrollment or a device
// sign-in is described by the Warden grant it produces: the base scopes on Warden, or the first grant the
// enrollment asks for, for the life of the family.
func (r Request) approvalRef(cfg Config) (approval.PrincipalRef, approval.Requested) {
	p := approval.PrincipalRef{Sub: r.Principal, Kind: r.PrincipalKind}
	if r.Requester != "" && r.Requester != r.Principal {
		p.Act = []approval.Party{{Sub: r.Requester, Kind: firstNonEmpty(r.Evidence["requester_kind"], KindHuman)}}
	}
	q := approval.Requested{Audience: r.Audience, Scopes: r.Scopes, TTLSeconds: r.TTLSeconds, Constraints: r.Constraints}
	if q.Audience == "" {
		q.Audience, q.Scopes = Audience, policy.BaseScopes
	}
	if q.TTLSeconds <= 0 {
		q.TTLSeconds = int64(cfg.MaxGrantTTL.Seconds())
	}
	return p, q
}

func (s *Service) seal(r *Request) {
	p, q := r.approvalRef(s.cfg)
	r.digest = approval.Digest(p, q, r.Tier)
}

// purposeLine is the text the approver reads: what is asked, then the requester's own words.
func (r Request) purposeLine() string {
	var head string
	switch policy.Action(r.Action) {
	case policy.ActionEnroll:
		head = "Enroll " + r.PrincipalKind + " " + r.Principal
		if d := r.Evidence["display"]; d != "" {
			head += " (" + d + ")"
		}
		if par := r.Evidence["parent"]; par != "" {
			head += " under " + par
		}
	case policy.ActionDevice:
		head = "Device sign-in as " + r.PrincipalKind + " " + r.Principal + ", code " + r.Evidence["user_code"]
	default:
		return cleanText(r.Purpose, 1024)
	}
	if r.Purpose != "" {
		head += ": " + r.Purpose
	}
	return cleanText(head, 1024)
}

func cleanText(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' {
			return -1
		}
		return r
	}, s))
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func cleanEvidence(in map[string]string) (map[string]string, error) {
	if len(in) > 16 {
		return nil, wrap(ErrInvalid, "at most 16 evidence fields")
	}
	out := map[string]string{}
	for k, v := range in {
		if len(k) == 0 || len(k) > 64 {
			return nil, wrap(ErrInvalid, "evidence keys are 1 to 64 characters")
		}
		out[k] = cleanText(v, 512)
	}
	return out, nil
}

// CreateRequest files a grant request. Policy assigns the tier: ground is granted at once; elevated and
// critical go to Gatecrasher; deny is recorded and refused.
func (s *Service) CreateRequest(ctx context.Context, c Caller, in RequestInput) (Request, error) {
	sub := in.Principal
	if sub == "" {
		sub = c.Sub
	}
	norm, err := scopes.Normalize(in.Audience, in.Scopes)
	if err != nil {
		return Request{}, wrap(ErrInvalid, "%v", err)
	}
	ttl := time.Duration(in.TTLSeconds) * time.Second
	if in.TTLSeconds < 0 || ttl > s.cfg.MaxGrantTTL {
		return Request{}, wrap(ErrInvalid, "ttl_seconds must be between 0 and %d", int64(s.cfg.MaxGrantTTL.Seconds()))
	}
	if ttl == 0 {
		ttl = s.cfg.DefaultGrantTTL
	}
	ev, err := cleanEvidence(in.Evidence)
	if err != nil {
		return Request{}, err
	}
	if len(mustJSON(in.Constraints)) > 4096 {
		return Request{}, wrap(ErrInvalid, "constraints are too large")
	}
	p, ok, err := s.principal(ctx, s.st.Reader(), sub)
	if err != nil {
		return Request{}, err
	}
	if !ok {
		return Request{}, wrap(ErrNotFound, "principal %s is not enrolled", sub)
	}
	if p.Disabled {
		return Request{}, wrap(ErrForbidden, "principal is disabled")
	}
	existing, err := s.grantsOf(ctx, s.st.Reader(), sub, in.Audience)
	if err != nil {
		return Request{}, err
	}
	renewal := false
	for _, g := range existing {
		if g.RevokedAt.IsZero() && s.now().Before(g.ExpiresAt.Add(7*24*time.Hour)) && scopes.Subset(norm, g.Scopes) {
			renewal = true
		}
	}
	r := Request{ID: newID("req"), Action: string(policy.ActionGrant), Principal: sub, PrincipalKind: p.Kind, Requester: c.Sub,
		Audience: in.Audience, Scopes: norm, TTLSeconds: int64(ttl.Seconds()), Constraints: in.Constraints,
		Purpose: cleanText(in.Purpose, 1024), Evidence: ev}
	v, err := s.classify(ctx, r.ID, policy.Facts{Action: policy.ActionGrant, Principal: sub, Kind: p.Kind, Requester: c.Sub,
		RequesterKind: c.Kind, RequesterAdmin: c.Admin && c.Human, ParentOfPrincipal: p.Parent != "" && p.Parent == c.Sub,
		Audience: in.Audience, Scopes: norm, TTL: ttl, Renewal: renewal})
	if err != nil {
		return Request{}, err
	}
	r.Tier, r.Rule = string(v.Tier), v.Rule
	if c.Sub != sub {
		r.Evidence["requester_kind"] = c.Kind
	}
	s.seal(&r)
	switch {
	case v.Tier == policy.Refused:
		r.Status = string(approval.Denied)
	case v.Tier == policy.Ground, v.Rule == "floor:owner-direct":
		r.Status = string(approval.Approved)
		r.DecidedBy = "policy:" + v.Rule
		if v.Rule == "floor:owner-direct" {
			r.DecidedBy = c.Sub
		}
	default:
		r.Status = string(approval.Pending)
		if v.ApproverClass != "" && v.Tier == policy.Elevated {
			r.Evidence["approver_class"] = v.ApproverClass
		}
	}
	err = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		r.GrantID = ""
		if r.Status == string(approval.Approved) {
			g, xerr := s.insertGrant(ctx, tx, newGrant{Principal: sub, Audience: r.Audience, Scopes: r.Scopes, Constraints: r.Constraints,
				Tier: r.Tier, Rule: r.Rule, Approver: r.DecidedBy, RequestID: r.ID, Evidence: r.Evidence, TTL: ttl})
			if xerr != nil {
				return xerr
			}
			r.GrantID = g.ID
		}
		return s.insertRequest(ctx, tx, &r)
	})
	if err != nil {
		return Request{}, err
	}
	if r.Status == string(approval.Pending) {
		s.submit(ctx, &r)
	}
	return r, nil
}

// submit sends a pending request to Gatecrasher. A failure is logged and retried by the worker.
func (s *Service) submit(ctx context.Context, r *Request) {
	if s.approver == nil || r.ApprovalID != "" {
		return
	}
	p, q := r.approvalRef(s.cfg)
	ar := approval.Request{IdempotencyKey: r.ID, Source: "warden", Kind: "credential_grant", Tier: r.Tier,
		ApproverClass: r.Evidence["approver_class"], Principal: p, Requested: q, Purpose: r.purposeLine(),
		Evidence:      approval.Evidence{TaskID: r.Evidence["task_id"], SessionID: r.Evidence["session_id"], PolicyRule: r.Rule},
		RequestDigest: r.digest, ExpiresAt: r.ExpiresAt}
	if ar.Tier != string(policy.Elevated) {
		ar.ApproverClass = ""
	} else if ar.ApproverClass == "" {
		ar.ApproverClass = "approve.credentials"
	}
	t, err := s.approver.Submit(ctx, ar)
	if err != nil {
		slog.Warn("warden: approval submit failed; will retry", "request", r.ID, "err", err)
		return
	}
	err = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		_, xerr := tx.ExecContext(ctx, `UPDATE requests SET approval_id = ?, updated_at = ? WHERE id = ? AND approval_id = ''`, t.ApprovalID, ts(s.now()), r.ID)
		return xerr
	})
	if err == nil {
		r.ApprovalID = t.ApprovalID
	}
}

// GetRequest returns a request the caller may see, after checking Gatecrasher once if it is pending.
func (s *Service) GetRequest(ctx context.Context, c Caller, id string) (Request, error) {
	r, err := s.loadRequest(ctx, s.st.Reader(), id)
	if err != nil {
		return Request{}, err
	}
	if !c.Admin && r.Principal != c.Sub && r.Requester != c.Sub {
		return Request{}, ErrNotFound
	}
	if r.Status == string(approval.Pending) {
		if err := s.Sync(ctx, r.ID, 0); err != nil {
			slog.Warn("warden: approval sync failed", "request", r.ID, "err", err)
		}
		return s.loadRequest(ctx, s.st.Reader(), id)
	}
	return r, nil
}

// ListRequests lists the caller's requests (as principal or requester), or every request for the owner.
func (s *Service) ListRequests(ctx context.Context, c Caller, all bool, status string) ([]Request, error) {
	q := `SELECT ` + reqCols + ` FROM requests WHERE 1 = 1`
	var args []any
	if !all || !c.Admin {
		q += ` AND (principal = ? OR requester = ?)`
		args = append(args, c.Sub, c.Sub)
	}
	if status != "" {
		q += ` AND status = ?`
		args = append(args, status)
	}
	rows, err := s.st.Reader().QueryContext(ctx, q+` ORDER BY created_at DESC LIMIT 200`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Request{}
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Withdraw cancels a pending request the caller filed (or any, for the owner).
func (s *Service) Withdraw(ctx context.Context, c Caller, id string) (Request, error) {
	r, err := s.loadRequest(ctx, s.st.Reader(), id)
	if err != nil {
		return Request{}, err
	}
	if !c.Admin && r.Requester != c.Sub && r.Principal != c.Sub {
		return Request{}, ErrNotFound
	}
	if r.Status != string(approval.Pending) {
		return Request{}, wrap(ErrConflict, "request is %s", r.Status)
	}
	if err := s.finish(ctx, r.ID, string(approval.Withdrawn), c.Sub, ""); err != nil {
		return Request{}, err
	}
	if s.approver != nil && r.ApprovalID != "" {
		if err := s.approver.Withdraw(ctx, r.ApprovalID); err != nil {
			slog.Warn("warden: approval withdraw failed", "request", r.ID, "err", err)
		}
	}
	return s.loadRequest(ctx, s.st.Reader(), id)
}

// finish moves a pending request to a terminal status that grants nothing.
func (s *Service) finish(ctx context.Context, id, status, by, decision string) error {
	return s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE requests SET status = ?, decided_by = ?, decision = ?, updated_at = ? WHERE id = ? AND status = 'pending'`,
			status, by, decision, ts(s.now()), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE enrollments SET status = 'refused' WHERE request_id = ? AND status = 'pending'`, id); err != nil {
			return err
		}
		ds := "denied"
		if status == string(approval.Expired) {
			ds = "expired"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE device_codes SET status = ? WHERE request_id = ? AND status = 'pending'`, ds, id); err != nil {
			return err
		}
		return s.audit(ctx, tx, by, "request."+status, id, nil)
	})
}

// Sync checks Gatecrasher for one pending request, waiting up to wait, and applies a verified decision.
func (s *Service) Sync(ctx context.Context, id string, wait time.Duration) error {
	r, err := s.loadRequest(ctx, s.st.Reader(), id)
	if err != nil || r.Status != string(approval.Pending) {
		return err
	}
	if !s.now().Before(r.ExpiresAt) {
		if s.approver != nil && r.ApprovalID != "" {
			_ = s.approver.Withdraw(ctx, r.ApprovalID)
		}
		return s.finish(ctx, r.ID, string(approval.Expired), "warden", "")
	}
	if s.approver == nil {
		return nil
	}
	if r.ApprovalID == "" {
		s.submit(ctx, &r)
		if r.ApprovalID == "" {
			return nil
		}
	}
	t, err := s.approver.Await(ctx, r.ApprovalID, wait)
	if err != nil {
		return err
	}
	switch t.Status {
	case approval.Pending:
		return nil
	case approval.Expired, approval.Withdrawn:
		return s.finish(ctx, r.ID, string(t.Status), "gatecrasher", "")
	case approval.Approved, approval.Denied:
	}
	_, q := r.approvalRef(s.cfg)
	d, err := s.decide.Verify(ctx, t.Decision, approval.Expect{Issuer: s.cfg.GatecrasherIssuer, ApprovalID: r.ApprovalID, RequestID: r.ID,
		Digest: r.digest, Tier: r.Tier, Requested: q, NotDeciders: []string{r.Principal, r.Requester}, Owner: s.cfg.ApprovalOwner})
	if err != nil {
		if errors.Is(err, approval.ErrDecision) {
			slog.Error("warden: refusing an approval decision", "request", r.ID, "err", err)
			_ = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
				return s.audit(ctx, tx, "gatecrasher", "decision.refused", r.ID, map[string]any{"reason": err.Error()})
			})
		}
		return err
	}
	if d.Outcome == approval.Denied {
		return s.finish(ctx, r.ID, string(approval.Denied), d.Decider.Sub, t.Decision)
	}
	return s.approve(ctx, r, d.Decider.Sub, t.Decision, d.Narrowed)
}

// approve applies an approval: a grant, a ready enrollment, or an approved device code.
func (s *Service) approve(ctx context.Context, r Request, by, decision string, n *approval.Narrowed) error {
	if n != nil {
		if len(n.Scopes) > 0 {
			r.Scopes = n.Scopes
		}
		if n.TTLSeconds > 0 {
			r.TTLSeconds = n.TTLSeconds
		}
	}
	return s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		cur, err := s.loadRequest(ctx, tx, r.ID)
		if err != nil || cur.Status != string(approval.Pending) {
			return err
		}
		grantID := ""
		switch policy.Action(r.Action) {
		case policy.ActionGrant:
			g, xerr := s.insertGrant(ctx, tx, newGrant{Principal: r.Principal, Audience: r.Audience, Scopes: r.Scopes, Constraints: r.Constraints,
				Tier: r.Tier, Rule: r.Rule, Approver: by, Approval: r.ApprovalID, RequestID: r.ID, Evidence: r.Evidence,
				TTL: time.Duration(r.TTLSeconds) * time.Second})
			if xerr != nil {
				return xerr
			}
			grantID = g.ID
		case policy.ActionEnroll, policy.ActionDevice:
			if grantID, err = s.admitPrincipal(ctx, tx, r, by); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE requests SET status = 'approved', decided_by = ?, decision = ?, grant_id = ?, updated_at = ?
			WHERE id = ?`, by, decision, grantID, ts(s.now()), r.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, by, "request.approved", r.ID, map[string]any{"grant": grantID, "tier": r.Tier})
	})
}

// RunWorker syncs pending requests until ctx ends.
func (s *Service) RunWorker(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s.syncPending(ctx)
		if err := s.reloadDeny(ctx); err != nil {
			slog.Warn("warden: deny-list reload failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) syncPending(ctx context.Context) {
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT id FROM requests WHERE status = 'pending' ORDER BY created_at LIMIT 100`)
	if err != nil {
		slog.Warn("warden: list pending requests", "err", err)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	_ = rows.Close()
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		if err := s.Sync(ctx, id, 0); err != nil && !errors.Is(err, approval.ErrDecision) {
			slog.Warn("warden: approval sync failed", "request", id, "err", err)
		}
	}
}
