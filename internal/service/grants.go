package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/hollis-labs/libs/core/store"

	"github.com/hollis-labs/warden/internal/policy"
	"github.com/hollis-labs/warden/internal/scopes"
)

// Principal is a credential holder.
type Principal struct {
	Sub       string    `json:"sub"`
	Kind      string    `json:"kind"`
	Display   string    `json:"display,omitempty"`
	Parent    string    `json:"parent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Disabled  bool      `json:"disabled,omitempty"`
}

// Grant is a durable, auditable authorization: one principal, one audience, a scope set.
type Grant struct {
	ID          string            `json:"id"`
	Principal   string            `json:"principal"`
	Audience    string            `json:"audience"`
	Scopes      []string          `json:"scopes"`
	Constraints map[string]any    `json:"constraints,omitempty"`
	Tier        string            `json:"tier"`
	Rule        string            `json:"rule,omitempty"`
	Approver    string            `json:"approver,omitempty"`
	ApprovalRef string            `json:"approval_ref,omitempty"`
	RequestID   string            `json:"request_id,omitempty"`
	Evidence    map[string]string `json:"evidence,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	LastUsedAt  time.Time         `json:"last_used_at,omitzero"`
	RevokedAt   time.Time         `json:"revoked_at,omitzero"`
	Reason      string            `json:"revoke_reason,omitempty"`
}

// Live reports whether g can mint at now.
func (g Grant) Live(now time.Time) bool { return g.RevokedAt.IsZero() && now.Before(g.ExpiresAt) }

func (s *Service) principal(ctx context.Context, q store.Querier, sub string) (Principal, bool, error) {
	var p Principal
	var parent, disabled sql.NullString
	var created string
	err := q.QueryRowContext(ctx, `SELECT sub, kind, display, parent, created_at, disabled_at FROM principals WHERE sub = ?`, sub).
		Scan(&p.Sub, &p.Kind, &p.Display, &parent, &created, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, false, nil
	}
	if err != nil {
		return Principal{}, false, err
	}
	p.Parent, p.CreatedAt, p.Disabled = parent.String, parseTS(created), disabled.Valid
	return p, true, nil
}

// GetPrincipal returns a principal by sub.
func (s *Service) GetPrincipal(ctx context.Context, sub string) (Principal, error) {
	p, ok, err := s.principal(ctx, s.st.Reader(), sub)
	if err != nil {
		return Principal{}, err
	}
	if !ok {
		return Principal{}, ErrNotFound
	}
	return p, nil
}

func (s *Service) createPrincipal(ctx context.Context, tx store.Tx, p Principal) error {
	var parent any
	if p.Parent != "" {
		parent = p.Parent
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO principals (sub, kind, display, parent, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (sub) DO NOTHING`, p.Sub, p.Kind, p.Display, parent, ts(s.now()))
	return err
}

const grantCols = `id, principal, audience, scopes, constraints, tier, rule, approver, approval_ref, request_id, evidence,
	created_at, expires_at, last_used_at, revoked_at, revoke_reason`

func scanGrant(sc interface{ Scan(...any) error }) (Grant, error) {
	var g Grant
	var scs, cons, ev, created, expires string
	var used, revoked sql.NullString
	if err := sc.Scan(&g.ID, &g.Principal, &g.Audience, &scs, &cons, &g.Tier, &g.Rule, &g.Approver, &g.ApprovalRef, &g.RequestID,
		&ev, &created, &expires, &used, &revoked, &g.Reason); err != nil {
		return Grant{}, err
	}
	g.Scopes = strings.Fields(scs)
	_ = json.Unmarshal([]byte(cons), &g.Constraints)
	_ = json.Unmarshal([]byte(ev), &g.Evidence)
	g.CreatedAt, g.ExpiresAt, g.LastUsedAt, g.RevokedAt = parseTS(created), parseTS(expires), nullTS(used), nullTS(revoked)
	return g, nil
}

func (s *Service) grantsOf(ctx context.Context, q store.Querier, principal, audience string) ([]Grant, error) {
	query := `SELECT ` + grantCols + ` FROM grants WHERE principal = ?`
	args := []any{principal}
	if audience != "" {
		query += ` AND audience = ?`
		args = append(args, audience)
	}
	rows, err := q.QueryContext(ctx, query+` ORDER BY created_at`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

type newGrant struct {
	Principal, Audience string
	Scopes              []string
	Constraints         map[string]any
	Tier, Rule          string
	Approver, Approval  string
	RequestID           string
	Evidence            map[string]string
	TTL                 time.Duration
}

func (s *Service) insertGrant(ctx context.Context, tx store.Tx, ng newGrant) (Grant, error) {
	now := s.now()
	ttl := ng.TTL
	if ttl <= 0 {
		ttl = s.cfg.DefaultGrantTTL
	}
	if ttl > s.cfg.MaxGrantTTL {
		ttl = s.cfg.MaxGrantTTL
	}
	g := Grant{ID: newID("grt"), Principal: ng.Principal, Audience: ng.Audience, Scopes: ng.Scopes, Constraints: ng.Constraints,
		Tier: ng.Tier, Rule: ng.Rule, Approver: ng.Approver, ApprovalRef: ng.Approval, RequestID: ng.RequestID, Evidence: ng.Evidence,
		CreatedAt: now, ExpiresAt: now.Add(ttl)}
	_, err := tx.ExecContext(ctx, `INSERT INTO grants (id, principal, audience, scopes, constraints, tier, rule, approver, approval_ref,
		request_id, evidence, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.Principal, g.Audience, strings.Join(g.Scopes, " "), mustJSON(g.Constraints), g.Tier, g.Rule, g.Approver, g.ApprovalRef,
		g.RequestID, mustJSON(g.Evidence), ts(g.CreatedAt), ts(g.ExpiresAt))
	if err != nil {
		return Grant{}, err
	}
	return g, s.audit(ctx, tx, firstNonEmpty(ng.Approver, "warden"), "grant.create", g.Principal,
		map[string]any{"grant": g.ID, "audience": g.Audience, "scopes": g.Scopes, "tier": g.Tier, "rule": g.Rule, "request": g.RequestID})
}

// baseGrant gives a new principal its Warden base scopes (policy.BaseScopes), so its parent credential
// can mint the token it uses to file requests. It is ground tier by the owner's rules.
func (s *Service) baseGrant(ctx context.Context, tx store.Tx, sub, requestID string) error {
	gs, err := s.grantsOf(ctx, tx, sub, Audience)
	if err != nil {
		return err
	}
	for _, g := range gs {
		if g.Live(s.now()) && scopes.Subset(policy.BaseScopes, g.Scopes) {
			return nil
		}
	}
	_, err = s.insertGrant(ctx, tx, newGrant{Principal: sub, Audience: Audience, Scopes: policy.BaseScopes, Tier: string(policy.Ground),
		Rule: "base", RequestID: requestID, TTL: s.cfg.MaxGrantTTL})
	return err
}

// ListGrants lists a principal's grants. A caller sees its own; the owner sees anyone's.
func (s *Service) ListGrants(ctx context.Context, c Caller, principal string) ([]Grant, error) {
	if principal == "" {
		principal = c.Sub
	}
	if principal != c.Sub && !c.Admin {
		return nil, ErrForbidden
	}
	gs, err := s.grantsOf(ctx, s.st.Reader(), principal, "")
	if gs == nil {
		gs = []Grant{}
	}
	return gs, err
}

// GetGrant returns one grant the caller may see.
func (s *Service) GetGrant(ctx context.Context, c Caller, id string) (Grant, error) {
	g, err := scanGrant(s.st.Reader().QueryRowContext(ctx, `SELECT `+grantCols+` FROM grants WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, err
	}
	if g.Principal != c.Sub && !c.Admin {
		return Grant{}, ErrNotFound
	}
	return g, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
