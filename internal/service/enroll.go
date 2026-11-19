package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/hollis-labs/libs/core/store"

	"github.com/hollis-labs/warden/internal/approval"
	"github.com/hollis-labs/warden/internal/issuer"
	"github.com/hollis-labs/warden/internal/policy"
	"github.com/hollis-labs/warden/internal/scopes"
)

// EnrollInput is an agent-facing enrollment: a principal that wants its first parent credential, and
// optionally the first grant it needs.
type EnrollInput struct {
	Sub        string            `json:"sub"`
	Kind       string            `json:"kind"`
	Display    string            `json:"display,omitempty"`
	Parent     string            `json:"parent,omitempty"` // a session's agent
	Audience   string            `json:"audience,omitempty"`
	Scopes     []string          `json:"scopes,omitempty"`
	TTLSeconds int64             `json:"ttl_seconds,omitempty"`
	Purpose    string            `json:"purpose,omitempty"`
	Evidence   map[string]string `json:"evidence,omitempty"`
}

// Enrollment is the answer to an enrollment. PollToken is shown once; the enrolling process keeps it to
// collect its parent credential.
type Enrollment struct {
	ID        string    `json:"enrollment_id"`
	RequestID string    `json:"request_id"`
	Status    string    `json:"status"` // pending, ready, delivered, refused
	Tier      string    `json:"tier"`
	PollToken string    `json:"poll_token,omitempty"`
	Interval  int       `json:"interval"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Enroll records an enrollment and its request. caller is nil for an unauthenticated enrollment; when set,
// it is recorded as the requester (a launcher enrolling a session it starts).
func (s *Service) Enroll(ctx context.Context, caller *Caller, in EnrollInput) (Enrollment, error) {
	if !ValidSub(in.Sub) {
		return Enrollment{}, wrap(ErrInvalid, "sub must be a Registry id (letters, digits and :/._@+-)")
	}
	if !ValidKind(in.Kind) {
		return Enrollment{}, wrap(ErrInvalid, "kind must be agent, session, machine, app or human")
	}
	if (in.Kind == KindSession) != (in.Parent != "") {
		return Enrollment{}, wrap(ErrInvalid, "a session names its agent as parent, and only a session has a parent")
	}
	var norm []string
	if in.Audience != "" {
		n, err := scopes.Normalize(in.Audience, in.Scopes)
		if err != nil {
			return Enrollment{}, wrap(ErrInvalid, "%v", err)
		}
		norm = n
	}
	ttl := time.Duration(in.TTLSeconds) * time.Second
	if in.TTLSeconds < 0 || ttl > s.cfg.MaxGrantTTL {
		return Enrollment{}, wrap(ErrInvalid, "ttl_seconds out of range")
	}
	ev, err := cleanEvidence(in.Evidence)
	if err != nil {
		return Enrollment{}, err
	}
	rd := s.st.Reader()
	_, exists, err := s.principal(ctx, rd, in.Sub)
	if err != nil {
		return Enrollment{}, err
	}
	parentOK := false
	if in.Parent != "" {
		par, ok, xerr := s.principal(ctx, rd, in.Parent)
		if xerr != nil {
			return Enrollment{}, xerr
		}
		if !ok || par.Kind != KindAgent || par.Disabled {
			return Enrollment{}, wrap(ErrInvalid, "a session's parent must be an enrolled agent")
		}
		parentOK = caller != nil && caller.Sub == in.Parent
	}
	var pending int
	if err = rd.QueryRowContext(ctx, `SELECT COUNT(*) FROM enrollments WHERE status = 'pending'`).Scan(&pending); err != nil {
		return Enrollment{}, err
	}
	if pending >= s.cfg.MaxPendingEnrollments {
		return Enrollment{}, wrap(ErrUnavailable, "too many pending enrollments")
	}
	f := policy.Facts{Action: policy.ActionEnroll, Principal: in.Sub, Kind: in.Kind, Audience: in.Audience, Scopes: norm, TTL: ttl,
		PrincipalExists: exists, ParentOfPrincipal: parentOK}
	r := Request{ID: newID("req"), Action: string(policy.ActionEnroll), Principal: in.Sub, PrincipalKind: in.Kind,
		Audience: in.Audience, Scopes: norm, TTLSeconds: int64(ttl.Seconds()), Purpose: cleanText(in.Purpose, 1024), Evidence: ev,
		ExpiresAt: s.now().Add(s.cfg.EnrollTTL)}
	if caller != nil {
		f.Requester, f.RequesterKind, f.RequesterAdmin = caller.Sub, caller.Kind, caller.Admin && caller.Human
		r.Requester = caller.Sub
	}
	if in.Display != "" {
		r.Evidence["display"] = cleanText(in.Display, 128)
	}
	if in.Parent != "" {
		r.Evidence["parent"] = in.Parent
	}
	v, err := s.classify(ctx, r.ID, f)
	if err != nil {
		return Enrollment{}, err
	}
	r.Tier, r.Rule = string(v.Tier), v.Rule
	r.Status = string(approval.Pending)
	if v.Tier == policy.Refused {
		r.Status = string(approval.Denied)
	}
	if v.ApproverClass != "" {
		r.Evidence["approver_class"] = v.ApproverClass
	}
	r.seal()
	poll := pollPrefix + randomString(32)
	e := Enrollment{ID: newID("enr"), RequestID: r.ID, Status: "pending", Tier: r.Tier, PollToken: poll, Interval: 5, ExpiresAt: r.ExpiresAt}
	if r.Status == string(approval.Denied) {
		e.Status, e.PollToken = "refused", ""
	}
	err = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		if err = s.insertRequest(ctx, tx, &r); err != nil {
			return err
		}
		_, xerr := tx.ExecContext(ctx, `INSERT INTO enrollments (id, request_id, sub, kind, display, parent, poll_hash, status, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, e.ID, r.ID, in.Sub, in.Kind, r.Evidence["display"], in.Parent, hashSecret(poll),
			e.Status, ts(s.now()), ts(e.ExpiresAt))
		return xerr
	})
	if err != nil {
		return Enrollment{}, err
	}
	if r.Status == string(approval.Pending) {
		// Ground (an agent enrolling its own session) and owner-direct need no outside decision.
		if v.Tier == policy.Ground || v.Rule == "floor:owner-direct" {
			by := "policy:" + v.Rule
			if caller != nil && v.Rule == "floor:owner-direct" {
				by = caller.Sub
			}
			if err := s.approve(ctx, r, by, "", nil); err != nil {
				return Enrollment{}, err
			}
			e.Status = "ready"
		} else {
			s.submit(ctx, &r)
		}
	}
	return e, nil
}

// admitPrincipal creates the principal of an approved enrollment or device code, its base grant and the
// optional requested grant, and marks the enrollment ready. It returns the requested grant's id.
func (s *Service) admitPrincipal(ctx context.Context, tx store.Tx, r Request, by string) (string, error) {
	p := Principal{Sub: r.Principal, Kind: r.PrincipalKind, Display: r.Evidence["display"], Parent: r.Evidence["parent"]}
	if err := s.createPrincipal(ctx, tx, p); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE principals SET disabled_at = NULL WHERE sub = ?`, p.Sub); err != nil {
		return "", err
	}
	if err := s.baseGrant(ctx, tx, p.Sub, r.ID); err != nil {
		return "", err
	}
	grantID := ""
	if r.Audience != "" && len(r.Scopes) > 0 {
		g, err := s.insertGrant(ctx, tx, newGrant{Principal: p.Sub, Audience: r.Audience, Scopes: r.Scopes, Tier: r.Tier, Rule: r.Rule,
			Approver: by, Approval: r.ApprovalID, RequestID: r.ID, Evidence: r.Evidence, TTL: time.Duration(r.TTLSeconds) * time.Second})
		if err != nil {
			return "", err
		}
		grantID = g.ID
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollments SET status = 'ready' WHERE request_id = ? AND status = 'pending'`, r.ID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_codes SET status = 'approved' WHERE request_id = ? AND status = 'pending'`, r.ID); err != nil {
		return "", err
	}
	return grantID, s.audit(ctx, tx, by, "principal.admit", p.Sub, map[string]any{"kind": p.Kind, "request": r.ID})
}

// Collected is a delivered parent credential.
type Collected struct {
	Sub              string    `json:"sub"`
	Kind             string    `json:"kind"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	Family           string    `json:"family"`
}

// PollEnrollment returns the enrollment's status, and once it is approved, its first parent credential,
// exactly once.
func (s *Service) PollEnrollment(ctx context.Context, id, pollToken string) (Enrollment, *Collected, error) {
	var e Enrollment
	var sub, kind, parent, hash, expires, reqID string
	err := s.st.Reader().QueryRowContext(ctx, `SELECT id, request_id, sub, kind, parent, poll_hash, status, expires_at FROM enrollments WHERE id = ?`, id).
		Scan(&e.ID, &reqID, &sub, &kind, &parent, &hash, &e.Status, &expires)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && hash != hashSecret(pollToken)) {
		return Enrollment{}, nil, ErrNotFound
	}
	if err != nil {
		return Enrollment{}, nil, err
	}
	e.RequestID, e.ExpiresAt, e.Interval = reqID, parseTS(expires), 5
	if e.Status == "pending" {
		if err = s.Sync(ctx, reqID, 0); err != nil && !errors.Is(err, approval.ErrDecision) {
			return e, nil, nil // still pending from the caller's view; the worker retries
		}
		if err = s.st.Reader().QueryRowContext(ctx, `SELECT status FROM enrollments WHERE id = ?`, id).Scan(&e.Status); err != nil {
			return Enrollment{}, nil, err
		}
	}
	switch e.Status {
	case "pending", "refused":
		return e, nil, nil
	case "delivered":
		return Enrollment{}, nil, wrap(ErrConflict, "this enrollment's credential was already collected")
	}
	var out *Collected
	err = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		out = nil
		res, xerr := tx.ExecContext(ctx, `UPDATE enrollments SET status = 'delivered', delivered_at = ? WHERE id = ? AND status = 'ready'`, ts(s.now()), id)
		if xerr != nil {
			return xerr
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return wrap(ErrConflict, "this enrollment's credential was already collected")
		}
		var act *issuer.Actor
		if parent != "" {
			act = &issuer.Actor{Sub: parent, Kind: KindAgent}
		}
		fid, secret, idle, ferr := s.newFamily(ctx, tx, sub, "enroll:"+id, act)
		if ferr != nil {
			return ferr
		}
		out = &Collected{Sub: sub, Kind: kind, RefreshToken: secret, RefreshExpiresAt: idle, Family: fid}
		return nil
	})
	if err != nil {
		return Enrollment{}, nil, err
	}
	e.Status = "delivered"
	return e, out, nil
}

// DeviceInput starts an RFC 8628 device authorization: an app (or a person's device) asks to become sub.
type DeviceInput struct {
	Sub     string `json:"client_id"`
	Kind    string `json:"kind,omitempty"` // default app
	Display string `json:"display,omitempty"`
}

// DeviceAuth is the RFC 8628 device authorization response.
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	RequestID               string `json:"request_id"`
}

const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ" // RFC 8628 §6.1: no vowels, no look-alikes

func userCode() string {
	var b strings.Builder
	for i := range 8 {
		if i == 4 {
			b.WriteByte('-')
		}
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeAlphabet))))
		b.WriteByte(userCodeAlphabet[n.Int64()])
	}
	return b.String()
}

// DeviceAuthorize starts a device authorization. The owner approves it (critical tier) in Gatecrasher, or
// directly with ApproveDevice.
func (s *Service) DeviceAuthorize(ctx context.Context, in DeviceInput) (DeviceAuth, error) {
	if in.Kind == "" {
		in.Kind = KindApp
	}
	if !ValidSub(in.Sub) || !ValidKind(in.Kind) || in.Kind == KindSession {
		return DeviceAuth{}, wrap(ErrInvalid, "client_id must be a principal id and kind one of agent, machine, app, human")
	}
	var pending int
	if err := s.st.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM device_codes WHERE status = 'pending' AND expires_at > ?`, ts(s.now())).Scan(&pending); err != nil {
		return DeviceAuth{}, err
	}
	if pending >= s.cfg.MaxPendingEnrollments {
		return DeviceAuth{}, wrap(ErrUnavailable, "too many pending device codes")
	}
	_, exists, err := s.principal(ctx, s.st.Reader(), in.Sub)
	if err != nil {
		return DeviceAuth{}, err
	}
	r := Request{ID: newID("req"), Action: string(policy.ActionDevice), Principal: in.Sub, PrincipalKind: in.Kind,
		Evidence: map[string]string{}, ExpiresAt: s.now().Add(s.cfg.DeviceTTL)}
	if in.Display != "" {
		r.Evidence["display"] = cleanText(in.Display, 128)
	}
	v, err := s.classify(ctx, r.ID, policy.Facts{Action: policy.ActionDevice, Principal: in.Sub, Kind: in.Kind, PrincipalExists: exists})
	if err != nil {
		return DeviceAuth{}, err
	}
	r.Tier, r.Rule, r.Status = string(v.Tier), v.Rule, string(approval.Pending)
	r.seal()
	code := devicePrefix + randomString(32)
	uc := userCode()
	r.Evidence["user_code"] = uc
	err = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		if err = s.insertRequest(ctx, tx, &r); err != nil {
			return err
		}
		_, xerr := tx.ExecContext(ctx, `INSERT INTO device_codes (id, request_id, device_hash, user_code, sub, kind, display, status,
			interval_seconds, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`, newID("dev"), r.ID, hashSecret(code), uc,
			in.Sub, in.Kind, r.Evidence["display"], int(s.cfg.DeviceInterval.Seconds()), ts(s.now()), ts(r.ExpiresAt))
		return xerr
	})
	if err != nil {
		return DeviceAuth{}, err
	}
	s.submit(ctx, &r)
	uri := s.cfg.VerificationURI
	return DeviceAuth{DeviceCode: code, UserCode: uc, VerificationURI: uri, VerificationURIComplete: uri + "?user_code=" + uc,
		ExpiresIn: int(s.cfg.DeviceTTL.Seconds()), Interval: int(s.cfg.DeviceInterval.Seconds()), RequestID: r.ID}, nil
}

// ApproveDevice is the owner deciding a device code directly (the CLI path while Gatecrasher's card is not
// wired). Only a human owner may.
func (s *Service) ApproveDevice(ctx context.Context, c Caller, code string, allow bool) (Request, error) {
	if !c.Admin || !c.Human {
		return Request{}, wrap(ErrForbidden, "only the owner approves a device sign-in")
	}
	var reqID string
	err := s.st.Reader().QueryRowContext(ctx, `SELECT request_id FROM device_codes WHERE user_code = ? AND status = 'pending' AND expires_at > ?`,
		strings.ToUpper(strings.TrimSpace(code)), ts(s.now())).Scan(&reqID)
	if errors.Is(err, sql.ErrNoRows) {
		return Request{}, wrap(ErrNotFound, "no pending device code %s", code)
	}
	if err != nil {
		return Request{}, err
	}
	r, err := s.loadRequest(ctx, s.st.Reader(), reqID)
	if err != nil {
		return Request{}, err
	}
	if !allow {
		err = s.finish(ctx, reqID, string(approval.Denied), c.Sub, "")
	} else {
		err = s.approve(ctx, r, c.Sub, "", nil)
	}
	if err != nil {
		return Request{}, err
	}
	if s.approver != nil && r.ApprovalID != "" {
		_ = s.approver.Withdraw(ctx, r.ApprovalID) // decided here; the card is no longer needed
	}
	return s.loadRequest(ctx, s.st.Reader(), reqID)
}

// DeviceToken redeems a device code (RFC 8628 §3.4): pending, slow_down, denied, expired, or the first
// access token (for Warden) and parent credential, exactly once.
func (s *Service) DeviceToken(ctx context.Context, code string) (Token, error) {
	if !strings.HasPrefix(code, devicePrefix) {
		return Token{}, wrap(ErrInvalidGrant, "not a device code")
	}
	var id, reqID, sub, status, expires string
	var interval int
	var last sql.NullString
	err := s.st.Reader().QueryRowContext(ctx, `SELECT id, request_id, sub, status, interval_seconds, last_poll_at, expires_at FROM device_codes
		WHERE device_hash = ?`, hashSecret(code)).Scan(&id, &reqID, &sub, &status, &interval, &last, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, wrap(ErrInvalidGrant, "unknown device code")
	}
	if err != nil {
		return Token{}, err
	}
	now := s.now()
	if status == "pending" && !now.Before(parseTS(expires)) {
		_ = s.finish(ctx, reqID, string(approval.Expired), "warden", "")
		return Token{}, ErrExpiredToken
	}
	if status == "pending" {
		slow := last.Valid && now.Sub(parseTS(last.String)) < time.Duration(interval)*time.Second
		_ = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
			_, xerr := tx.ExecContext(ctx, `UPDATE device_codes SET last_poll_at = ? WHERE id = ?`, ts(now), id)
			return xerr
		})
		if slow {
			return Token{}, ErrSlowDown
		}
		_ = s.Sync(ctx, reqID, 0)
		if err = s.st.Reader().QueryRowContext(ctx, `SELECT status FROM device_codes WHERE id = ?`, id).Scan(&status); err != nil {
			return Token{}, err
		}
	}
	switch status {
	case "pending":
		return Token{}, ErrAuthorizationPending
	case "denied":
		return Token{}, ErrAccessDenied
	case "expired":
		return Token{}, ErrExpiredToken
	case "consumed":
		return Token{}, wrap(ErrInvalidGrant, "device code already used")
	}
	var out Token
	err = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		res, xerr := tx.ExecContext(ctx, `UPDATE device_codes SET status = 'consumed' WHERE id = ? AND status = 'approved'`, id)
		if xerr != nil {
			return xerr
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return wrap(ErrInvalidGrant, "device code already used")
		}
		p, ok, cerr := s.principal(ctx, tx, sub)
		if cerr != nil || !ok {
			return wrap(ErrInvalidGrant, "principal missing")
		}
		fid, secret, idle, cerr := s.newFamily(ctx, tx, sub, "device:"+id, nil)
		if cerr != nil {
			return cerr
		}
		fam, cerr := s.loadFamily(ctx, tx, fid)
		if cerr != nil {
			return cerr
		}
		tok, cerr := s.mintTx(ctx, tx, p, fam, MintRequest{Audience: Audience}, fam.ExpiresAt)
		if cerr != nil {
			return cerr
		}
		tok.RefreshToken, tok.RefreshExpiresAt = secret, idle
		out = tok
		return nil
	})
	return out, err
}
