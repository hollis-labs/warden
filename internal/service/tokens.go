package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hollis-labs/libs/core/store"
	libauth "github.com/hollis-labs/libs/security/auth"

	"github.com/hollis-labs/warden/internal/issuer"
	"github.com/hollis-labs/warden/internal/scopes"
)

// Token is an issued access token, plus the rotated parent credential when the call consumed one. The
// response shape carries both the OAuth names (access_token, expires_in, refresh_token) and the names
// libs/security/auth's HTTPMinter reads (token, expires_at, ttl_seconds).
type Token struct {
	AccessToken  string    `json:"access_token"`
	Token        string    `json:"token"`
	TokenType    string    `json:"token_type"`
	IssuedType   string    `json:"issued_token_type,omitempty"`
	ExpiresIn    int       `json:"expires_in"`
	TTL          int       `json:"ttl_seconds"`
	ExpiresAt    time.Time `json:"expires_at"`
	Audience     string    `json:"aud"`
	Scope        string    `json:"scope"`
	Grant        string    `json:"grant,omitempty"`
	Sub          string    `json:"sub"`
	Kind         string    `json:"kind"`
	JTI          string    `json:"jti"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	// RefreshExpiresAt is when the new parent credential goes idle unless used.
	RefreshExpiresAt time.Time `json:"refresh_expires_at,omitzero"`
}

// MintRequest is what a caller asks a token for.
type MintRequest struct {
	Audience string
	Scopes   []string // empty: every scope of the chosen grant
	TTL      time.Duration
}

type family struct {
	ID, Principal, Origin string
	Actor                 *issuer.Actor
	ExpiresAt, RevokedAt  time.Time
}

func (s *Service) loadFamily(ctx context.Context, q store.Querier, id string) (family, error) {
	var f family
	var actor, exp string
	var revoked sql.NullString
	err := q.QueryRowContext(ctx, `SELECT id, principal, origin, actor, expires_at, revoked_at FROM families WHERE id = ?`, id).
		Scan(&f.ID, &f.Principal, &f.Origin, &actor, &exp, &revoked)
	if err != nil {
		return family{}, err
	}
	if actor != "" {
		f.Actor = &issuer.Actor{}
		if json.Unmarshal([]byte(actor), f.Actor) != nil {
			f.Actor = nil
		}
	}
	f.ExpiresAt, f.RevokedAt = parseTS(exp), nullTS(revoked)
	return f, nil
}

// newFamily starts a credential family for principal and returns its first parent credential (the only
// time the secret exists outside the caller: the store keeps its hash).
func (s *Service) newFamily(ctx context.Context, tx store.Tx, principal, origin string, actor *issuer.Actor) (string, string, time.Time, error) {
	now := s.now()
	fid := newID("fam")
	actorJSON := ""
	if actor != nil {
		b, _ := json.Marshal(actor)
		actorJSON = string(b)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO families (id, principal, origin, actor, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		fid, principal, origin, actorJSON, ts(now), ts(now.Add(s.cfg.FamilyLifetime))); err != nil {
		return "", "", time.Time{}, err
	}
	secret, idle, err := s.newParent(ctx, tx, fid)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return fid, secret, idle, s.audit(ctx, tx, principal, "family.create", principal, map[string]any{"family": fid, "origin": origin})
}

func (s *Service) newParent(ctx context.Context, tx store.Tx, fid string) (string, time.Time, error) {
	now := s.now()
	secret := parentPrefix + randomString(32)
	idle := now.Add(s.cfg.ParentIdle)
	_, err := tx.ExecContext(ctx, `INSERT INTO parents (id, family, hash, status, created_at, idle_expires_at) VALUES (?, ?, ?, 'active', ?, ?)`,
		newID("par"), fid, hashSecret(secret), ts(now), ts(idle))
	return secret, idle, err
}

// Refresh redeems a parent credential: it rotates the parent (the old one stops working) and mints an access
// token for one audience inside a live grant. A parent that was already rotated is a replay: the whole
// family is revoked and every token it minted is denied.
func (s *Service) Refresh(ctx context.Context, secret string, mr MintRequest) (Token, error) {
	if !strings.HasPrefix(secret, parentPrefix) {
		return Token{}, wrap(ErrInvalidGrant, "not a parent credential")
	}
	var out Token
	var reused string
	err := s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		out, reused = Token{}, ""
		var pid, fid, status, idle string
		err := tx.QueryRowContext(ctx, `SELECT id, family, status, idle_expires_at FROM parents WHERE hash = ?`, hashSecret(secret)).
			Scan(&pid, &fid, &status, &idle)
		if errors.Is(err, sql.ErrNoRows) {
			return wrap(ErrInvalidGrant, "unknown parent credential")
		}
		if err != nil {
			return err
		}
		fam, err := s.loadFamily(ctx, tx, fid)
		if err != nil {
			return err
		}
		now := s.now()
		switch {
		case !fam.RevokedAt.IsZero():
			return wrap(ErrInvalidGrant, "credential family revoked")
		case status == "rotated":
			if err = s.revokeFamilyTx(ctx, tx, fid, "reuse detected", "warden"); err != nil {
				return err
			}
			reused = fid
			return nil // commit the revocation
		case status != "active":
			return wrap(ErrInvalidGrant, "parent credential revoked")
		case !now.Before(parseTS(idle)), !now.Before(fam.ExpiresAt):
			return wrap(ErrInvalidGrant, "parent credential expired")
		}
		p, ok, err := s.principal(ctx, tx, fam.Principal)
		if err != nil {
			return err
		}
		if !ok || p.Disabled || s.Deny.Denied(libauth.Principal{ID: p.Sub}) {
			return wrap(ErrInvalidGrant, "principal disabled")
		}
		// Choose the grant and mint before rotating: a refused mint must not cost the caller its parent.
		tok, err := s.mintTx(ctx, tx, p, fam, mr, fam.ExpiresAt)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE parents SET status = 'rotated', used_at = ? WHERE id = ? AND status = 'active'`, ts(now), pid)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return wrap(ErrInvalidGrant, "parent credential already used")
		}
		next, nextIdle, err := s.newParent(ctx, tx, fid)
		if err != nil {
			return err
		}
		tok.RefreshToken, tok.RefreshExpiresAt = next, nextIdle
		out = tok
		return nil
	})
	if err != nil {
		return Token{}, err
	}
	if reused != "" {
		slog.Warn("warden: parent credential replayed; family revoked", "family", reused)
		if err := s.reloadDeny(ctx); err != nil {
			slog.Error("warden: deny-list reload failed", "err", err)
		}
		return Token{}, wrap(ErrInvalidGrant, "parent credential reuse detected; the credential family is revoked")
	}
	return out, nil
}

// mintTx picks the grant that covers mr for p and signs a token bounded by the grant, the kind's TTL and
// limit (the family's or the subject token's end).
func (s *Service) mintTx(ctx context.Context, tx store.Tx, p Principal, fam family, mr MintRequest, limit time.Time) (Token, error) {
	aud := mr.Audience
	if aud == "" {
		aud = Audience
	}
	if !scopes.ValidAudience(aud) {
		return Token{}, wrap(ErrInvalid, "audience must be one app id")
	}
	var want []string
	if len(mr.Scopes) > 0 {
		n, err := scopes.Normalize(aud, mr.Scopes)
		if err != nil {
			return Token{}, wrap(ErrInvalidScope, "%v", err)
		}
		want = n
	}
	gs, err := s.grantsOf(ctx, tx, p.Sub, aud)
	if err != nil {
		return Token{}, err
	}
	now := s.now()
	var best *Grant
	for i := range gs {
		g := gs[i]
		if !g.Live(now) || s.Deny.Denied(libauth.Principal{ID: "grant:" + g.ID}) {
			continue
		}
		if want != nil && !scopes.Subset(want, g.Scopes) {
			continue
		}
		if best == nil || g.ExpiresAt.After(best.ExpiresAt) {
			best = &gs[i]
		}
	}
	if best == nil {
		return Token{}, wrap(ErrInvalidScope, "no live grant covers audience %s with those scopes", aud)
	}
	if want == nil {
		want = best.Scopes
	}
	ttl := s.cfg.AccessTTL[p.Kind]
	if mr.TTL < 0 {
		return Token{}, wrap(ErrInvalid, "ttl must be positive")
	}
	if mr.TTL > 0 && mr.TTL < ttl {
		ttl = mr.TTL
	}
	exp := now.Add(ttl)
	for _, end := range []time.Time{best.ExpiresAt, limit} {
		if !end.IsZero() && end.Before(exp) {
			exp = end
		}
	}
	if !exp.After(now.Add(time.Second)) {
		return Token{}, wrap(ErrInvalidGrant, "the credential is about to expire")
	}
	c := issuer.Claims{Iss: s.cfg.Issuer, Sub: p.Sub, Aud: aud, Scope: strings.Join(want, " "), Iat: now.Unix(), Nbf: now.Unix(),
		Exp: exp.Unix(), JTI: uuid.NewString(), Kind: p.Kind, SID: fam.ID, Par: fam.ID, Grant: best.ID, Act: fam.Actor}
	return s.signTx(ctx, tx, c, best.ID)
}

func (s *Service) signTx(ctx context.Context, tx store.Tx, c issuer.Claims, grantID string) (Token, error) {
	tok, _, err := s.keys.Sign(c)
	if err != nil {
		return Token{}, err
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO minted (jti, family, grant_id, sub, aud, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		c.JTI, c.Par, grantID, c.Sub, c.Aud, ts(time.Unix(c.Exp, 0))); err != nil {
		return Token{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE grants SET last_used_at = ? WHERE id = ?`, ts(now), grantID); err != nil {
		return Token{}, err
	}
	ttl := int(time.Unix(c.Exp, 0).Sub(now).Seconds())
	return Token{AccessToken: tok, Token: tok, TokenType: "Bearer", ExpiresIn: ttl, TTL: ttl, ExpiresAt: time.Unix(c.Exp, 0).UTC(),
		Audience: c.Aud, Scope: c.Scope, Grant: grantID, Sub: c.Sub, Kind: c.Kind, JTI: c.JTI}, nil
}

// VerifyOwn verifies a token Warden issued, including the deny-list. aud "" accepts any audience.
func (s *Service) VerifyOwn(token, aud string) (issuer.Claims, error) {
	c, err := s.keys.Verify(token, s.cfg.Issuer, s.now())
	if err != nil {
		return issuer.Claims{}, wrap(ErrInvalidGrant, "token does not verify")
	}
	if aud != "" && c.Aud != aud {
		return issuer.Claims{}, wrap(ErrInvalidGrant, "token is for another audience")
	}
	if s.Deny.Denied(libauth.Principal{ID: c.Sub, TokenID: c.JTI, SessionID: c.SID}) ||
		(c.Grant != "" && s.Deny.Denied(libauth.Principal{ID: "grant:" + c.Grant})) {
		return issuer.Claims{}, wrap(ErrInvalidGrant, "token revoked")
	}
	return c, nil
}

// ExchangeRequest is an RFC 8693 token exchange.
type ExchangeRequest struct {
	SubjectToken string
	ActorToken   string // optional: the actor becomes the outermost act link
	MintRequest
}

// MaxActDepth bounds the actor chain.
const MaxActDepth = 4

// Exchange mints a narrower token from a Warden token. Narrowing only: the same audience may drop scopes and
// time; a different audience needs a subject token for Warden itself (resource servers never receive those,
// so they cannot exchange a token they were handed) and a live grant of the subject for the new audience.
func (s *Service) Exchange(ctx context.Context, er ExchangeRequest) (Token, error) {
	sub, err := s.VerifyOwn(er.SubjectToken, "")
	if err != nil {
		return Token{}, err
	}
	act := sub.Act
	if er.ActorToken != "" {
		a, xerr := s.VerifyOwn(er.ActorToken, Audience)
		if xerr != nil {
			return Token{}, wrap(ErrInvalidGrant, "actor token does not verify")
		}
		act = &issuer.Actor{Sub: a.Sub, Kind: a.Kind, Act: a.Act}
		if a.Sub == sub.Sub {
			act = sub.Act // acting as oneself adds nothing
		}
	}
	if act.Depth() > MaxActDepth {
		return Token{}, wrap(ErrInvalid, "actor chain too deep")
	}
	aud := er.Audience
	if aud == "" {
		aud = sub.Aud
	}
	end := time.Unix(sub.Exp, 0)
	var out Token
	err = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		p, ok, xerr := s.principal(ctx, tx, sub.Sub)
		if xerr != nil {
			return xerr
		}
		if !ok || p.Disabled {
			return wrap(ErrInvalidGrant, "principal disabled")
		}
		fam := family{ID: sub.Par, Principal: sub.Sub, Actor: act}
		if aud == sub.Aud {
			want := sub.Scopes()
			if len(er.Scopes) > 0 {
				n, xerr := scopes.Normalize(aud, er.Scopes)
				if xerr != nil {
					return wrap(ErrInvalidScope, "%v", xerr)
				}
				if !scopes.Subset(n, want) {
					return wrap(ErrInvalidScope, "exchange may only narrow scopes")
				}
				want = n
			}
			// Re-check the grant: a revoked or expired grant cannot be extended by exchanging.
			g, xerr := scanGrant(tx.QueryRowContext(ctx, `SELECT `+grantCols+` FROM grants WHERE id = ?`, sub.Grant))
			if xerr != nil || !g.Live(s.now()) || g.Principal != sub.Sub || g.Audience != aud {
				return wrap(ErrInvalidGrant, "the subject token's grant is no longer live")
			}
			ttl := time.Until(end)
			if er.TTL > 0 && er.TTL < ttl {
				ttl = er.TTL
			}
			exp := s.now().Add(ttl)
			if end.Before(exp) {
				exp = end
			}
			if g.ExpiresAt.Before(exp) {
				exp = g.ExpiresAt
			}
			now := s.now()
			if !exp.After(now.Add(time.Second)) {
				return wrap(ErrInvalidGrant, "the subject token is about to expire")
			}
			c := issuer.Claims{Iss: s.cfg.Issuer, Sub: sub.Sub, Aud: aud, Scope: strings.Join(want, " "), Iat: now.Unix(), Nbf: now.Unix(),
				Exp: exp.Unix(), JTI: uuid.NewString(), Kind: sub.Kind, SID: sub.SID, Par: sub.Par, Grant: g.ID, Act: act}
			out, err = s.signTx(ctx, tx, c, g.ID)
			return err
		}
		if sub.Aud != Audience {
			return wrap(ErrInvalidScope, "only a token for %s may be exchanged for another audience", Audience)
		}
		out, err = s.mintTx(ctx, tx, p, fam, MintRequest{Audience: aud, Scopes: er.Scopes, TTL: er.TTL}, end)
		return err
	})
	if err != nil {
		return Token{}, err
	}
	out.IssuedType = "urn:ietf:params:oauth:token-type:access_token"
	return out, nil
}

// revokeFamilyTx revokes a family, its parents, and denies every unexpired token it minted (by sid, which is
// the family id, until the longest such token could live).
func (s *Service) revokeFamilyTx(ctx context.Context, tx store.Tx, fid, reason, actor string) error {
	now := s.now()
	if _, err := tx.ExecContext(ctx, `UPDATE families SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL`,
		ts(now), reason, fid); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE parents SET status = 'revoked' WHERE family = ?`, fid); err != nil {
		return err
	}
	var last sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT MAX(expires_at) FROM minted WHERE family = ?`, fid).Scan(&last); err != nil {
		return err
	}
	if until := nullTS(last); until.After(now) {
		if err := s.denyTx(ctx, tx, "sid", fid, until.Add(issuer.Leeway), reason); err != nil {
			return err
		}
	}
	return s.audit(ctx, tx, actor, "family.revoke", fid, map[string]any{"reason": reason})
}

func (s *Service) denyTx(ctx context.Context, tx store.Tx, kind, value string, until time.Time, reason string) error {
	var u any
	if !until.IsZero() {
		u = ts(until)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO deny (kind, value, until, reason, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (kind, value) DO UPDATE SET until = excluded.until, reason = excluded.reason`, kind, value, u, reason, ts(s.now()))
	return err
}

// DenyListDoc returns the deny-list document (libs auth wire format) and its ETag.
func (s *Service) DenyListDoc() ([]byte, string) {
	s.denyMu.Lock()
	defer s.denyMu.Unlock()
	return s.denyBody, s.denyETag
}

// reloadDeny rebuilds the in-process list and the published document from the table. Grant revocations are
// kept in-process as sub "grant:<id>" and published as the jtis that grant minted, so resource servers (which
// do not know grants) still refuse them.
func (s *Service) reloadDeny(ctx context.Context) error {
	now := ts(s.now())
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT kind, value FROM deny WHERE until IS NULL OR until > ?`, now)
	if err != nil {
		return err
	}
	doc := libauth.DenyListDoc{JTI: []string{}, Sub: []string{}, SID: []string{}}
	local := libauth.DenyListDoc{}
	for rows.Next() {
		var kind, value string
		if err := rows.Scan(&kind, &value); err != nil {
			_ = rows.Close()
			return err
		}
		switch kind {
		case "jti":
			doc.JTI = append(doc.JTI, value)
		case "sid":
			doc.SID = append(doc.SID, value)
		case "sub":
			if strings.HasPrefix(value, "grant:") {
				local.Sub = append(local.Sub, value)
				continue
			}
			doc.Sub = append(doc.Sub, value)
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(local.Sub) > 0 {
		args := []any{now}
		marks := make([]string, 0, len(local.Sub))
		for _, g := range local.Sub {
			args = append(args, strings.TrimPrefix(g, "grant:"))
			marks = append(marks, "?")
		}
		jrows, err := s.st.Reader().QueryContext(ctx, `SELECT jti FROM minted WHERE expires_at > ? AND grant_id IN (`+strings.Join(marks, ",")+`)`, args...)
		if err != nil {
			return err
		}
		for jrows.Next() {
			var j string
			if err := jrows.Scan(&j); err != nil {
				_ = jrows.Close()
				return err
			}
			doc.JTI = append(doc.JTI, j)
		}
		_ = jrows.Close()
		if err := jrows.Err(); err != nil {
			return err
		}
	}
	all := libauth.DenyListDoc{JTI: doc.JTI, SID: doc.SID, Sub: append(append([]string{}, doc.Sub...), local.Sub...)}
	s.Deny.Replace(all)
	body, _ := json.Marshal(doc)
	s.denyMu.Lock()
	s.denyBody, s.denyETag = body, fmt.Sprintf(`"%s"`, hashSecret(string(body))[:16])
	s.denyMu.Unlock()
	return nil
}
