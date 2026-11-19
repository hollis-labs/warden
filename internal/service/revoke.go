package service

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hollis-labs/libs/core/store"

	"github.com/hollis-labs/warden/internal/issuer"
)

// RevokeGrant revokes a grant: it mints nothing more, and every unexpired token it minted is denied. The
// grant's principal may revoke its own grant; the owner may revoke any.
func (s *Service) RevokeGrant(ctx context.Context, c Caller, id, reason string) (Grant, error) {
	g, err := s.GetGrant(ctx, c, id)
	if err != nil {
		return Grant{}, err
	}
	if !g.RevokedAt.IsZero() {
		return g, nil
	}
	reason = cleanText(firstNonEmpty(reason, "revoked by "+c.Sub), 256)
	err = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		now := s.now()
		if _, err = tx.ExecContext(ctx, `UPDATE grants SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL`, ts(now), reason, id); err != nil {
			return err
		}
		var last sql.NullString
		if err = tx.QueryRowContext(ctx, `SELECT MAX(expires_at) FROM minted WHERE grant_id = ?`, id).Scan(&last); err != nil {
			return err
		}
		if until := nullTS(last); until.After(now) {
			if err = s.denyTx(ctx, tx, "sub", "grant:"+id, until.Add(issuer.Leeway), reason); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, c.Sub, "grant.revoke", g.Principal, map[string]any{"grant": id, "reason": reason})
	})
	if err != nil {
		return Grant{}, err
	}
	if err := s.reloadDeny(ctx); err != nil {
		return Grant{}, err
	}
	return s.GetGrant(ctx, c, id)
}

// Family is a parent-credential family, safe to list (no secret, no hash).
type Family struct {
	ID        string    `json:"id"`
	Principal string    `json:"principal"`
	Origin    string    `json:"origin"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at,omitzero"`
	Reason    string    `json:"revoke_reason,omitempty"`
}

// ListFamilies lists a principal's credential families.
func (s *Service) ListFamilies(ctx context.Context, c Caller, principal string) ([]Family, error) {
	if principal == "" {
		principal = c.Sub
	}
	if principal != c.Sub && !c.Admin {
		return nil, ErrForbidden
	}
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT id, principal, origin, created_at, expires_at, revoked_at, revoke_reason FROM families
		WHERE principal = ? ORDER BY created_at`, principal)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Family{}
	for rows.Next() {
		var f Family
		var created, expires string
		var revoked sql.NullString
		if err := rows.Scan(&f.ID, &f.Principal, &f.Origin, &created, &expires, &revoked, &f.Reason); err != nil {
			return nil, err
		}
		f.CreatedAt, f.ExpiresAt, f.RevokedAt = parseTS(created), parseTS(expires), nullTS(revoked)
		out = append(out, f)
	}
	return out, rows.Err()
}

// RevokeFamily revokes one credential family (a lost or leaked parent credential).
func (s *Service) RevokeFamily(ctx context.Context, c Caller, id, reason string) error {
	var principal string
	err := s.st.Reader().QueryRowContext(ctx, `SELECT principal FROM families WHERE id = ?`, id).Scan(&principal)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && principal != c.Sub && !c.Admin) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	reason = cleanText(firstNonEmpty(reason, "revoked by "+c.Sub), 256)
	if err := s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		return s.revokeFamilyTx(ctx, tx, id, reason, c.Sub)
	}); err != nil {
		return err
	}
	return s.reloadDeny(ctx)
}

// DisablePrincipal is the owner cutting a principal off: disabled, every family revoked, sub denied for as
// long as any token for it could live.
func (s *Service) DisablePrincipal(ctx context.Context, c Caller, sub, reason string) error {
	if !c.Admin {
		return ErrForbidden
	}
	reason = cleanText(firstNonEmpty(reason, "disabled by "+c.Sub), 256)
	err := s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE principals SET disabled_at = ? WHERE sub = ? AND disabled_at IS NULL`, ts(s.now()), sub)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if _, ok, xerr := s.principal(ctx, tx, sub); xerr != nil || !ok {
				return ErrNotFound
			}
		}
		rows, err := tx.QueryContext(ctx, `SELECT id FROM families WHERE principal = ? AND revoked_at IS NULL`, sub)
		if err != nil {
			return err
		}
		var fams []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			fams = append(fams, id)
		}
		_ = rows.Close()
		for _, f := range fams {
			if err := s.revokeFamilyTx(ctx, tx, f, reason, c.Sub); err != nil {
				return err
			}
		}
		maxTTL := time.Duration(0)
		for _, d := range s.cfg.AccessTTL {
			maxTTL = max(maxTTL, d)
		}
		if err := s.denyTx(ctx, tx, "sub", sub, s.now().Add(maxTTL+issuer.Leeway), reason); err != nil {
			return err
		}
		return s.audit(ctx, tx, c.Sub, "principal.disable", sub, map[string]any{"reason": reason})
	})
	if err != nil {
		return err
	}
	return s.reloadDeny(ctx)
}

// AuditEntry is one audit row.
type AuditEntry struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Subject string    `json:"subject,omitempty"`
	Detail  string    `json:"detail"`
}

// Audit lists recent audit rows, newest first, optionally for one subject. Owner only.
func (s *Service) Audit(ctx context.Context, c Caller, subject string, limit int) ([]AuditEntry, error) {
	if !c.Admin {
		return nil, ErrForbidden
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, at, actor, action, subject, detail FROM audit`
	var args []any
	if subject != "" {
		q += ` WHERE subject = ?`
		args = append(args, subject)
	}
	args = append(args, limit)
	rows, err := s.st.Reader().QueryContext(ctx, q+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Subject, &e.Detail); err != nil {
			return nil, err
		}
		e.At = parseTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// RotateKeys rotates the signing key (owner only). The old key keeps verifying for the overlap window.
func (s *Service) RotateKeys(ctx context.Context, c Caller) ([]string, error) {
	if !c.Admin {
		return nil, ErrForbidden
	}
	if err := s.keys.Rotate(); err != nil {
		return nil, err
	}
	err := s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		return s.audit(ctx, tx, c.Sub, "keys.rotate", "", map[string]any{"kids": s.keys.KIDs()})
	})
	return s.keys.KIDs(), err
}

// PruneMinted drops minted rows and deny entries that have expired.
func (s *Service) PruneMinted(ctx context.Context) error {
	now := ts(s.now())
	return s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM minted WHERE expires_at < ?`, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM deny WHERE until IS NOT NULL AND until < ?`, now)
		return err
	})
}
