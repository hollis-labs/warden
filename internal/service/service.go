// Package service is Warden's service layer: the only place that runs SQL. It owns principals, grants,
// parent-credential families, token minting and exchange, requests and their tiers, enrollment, device
// authorization, revocation and the audit trail. Transports (internal/api, internal/mcp, the CLI) call it
// and never the store.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hollis-labs/libs/core/store"
	libauth "github.com/hollis-labs/libs/security/auth"
	libpolicy "github.com/hollis-labs/libs/security/policy"

	"github.com/hollis-labs/warden/internal/approval"
	"github.com/hollis-labs/warden/internal/issuer"
	"github.com/hollis-labs/warden/internal/policy"
)

// Kinds of principal.
const (
	KindAgent   = "agent"
	KindSession = "session"
	KindMachine = "machine"
	KindApp     = "app"
	KindHuman   = "human"
)

// ValidKind reports whether k is a principal kind.
func ValidKind(k string) bool {
	return k == KindAgent || k == KindSession || k == KindMachine || k == KindApp || k == KindHuman
}

// Audience is Warden's own audience.
const Audience = "warden"

// Config holds the token rules. Zero values take the defaults below.
type Config struct {
	Issuer string // iss of every token
	// AccessTTL per principal kind. Design §4: agent and session 15 minutes, app 60 minutes.
	AccessTTL map[string]time.Duration
	// FamilyLifetime bounds a parent-credential family from its first use; ParentIdle bounds one member.
	FamilyLifetime time.Duration
	ParentIdle     time.Duration
	// DefaultGrantTTL and MaxGrantTTL bound grants.
	DefaultGrantTTL time.Duration
	MaxGrantTTL     time.Duration
	// RequestTTL is how long a request may stay pending.
	RequestTTL time.Duration
	// EnrollTTL is how long an enrollment may wait to be collected.
	EnrollTTL time.Duration
	// Device code lifetime and minimum poll interval (RFC 8628).
	DeviceTTL      time.Duration
	DeviceInterval time.Duration
	// VerificationURI is where a person goes to approve a device code (Gatecrasher's card, or Warden's
	// instructions page).
	VerificationURI string
	// GatecrasherIssuer is the iss of signed decisions.
	GatecrasherIssuer string
	// MaxPendingEnrollments bounds the open enrollment endpoint.
	MaxPendingEnrollments int
}

func (c *Config) defaults() {
	if c.Issuer == "" {
		c.Issuer = "warden"
	}
	def := map[string]time.Duration{KindAgent: 15 * time.Minute, KindSession: 15 * time.Minute, KindHuman: 15 * time.Minute,
		KindApp: 60 * time.Minute, KindMachine: 60 * time.Minute}
	if c.AccessTTL == nil {
		c.AccessTTL = def
	}
	for k, v := range def {
		if c.AccessTTL[k] <= 0 {
			c.AccessTTL[k] = v
		}
	}
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	set(&c.FamilyLifetime, 90*24*time.Hour)
	set(&c.ParentIdle, 30*24*time.Hour)
	set(&c.DefaultGrantTTL, 30*24*time.Hour)
	set(&c.MaxGrantTTL, 90*24*time.Hour)
	set(&c.RequestTTL, 7*24*time.Hour)
	set(&c.EnrollTTL, 24*time.Hour)
	set(&c.DeviceTTL, 15*time.Minute)
	set(&c.DeviceInterval, 5*time.Second)
	if c.MaxPendingEnrollments <= 0 {
		c.MaxPendingEnrollments = 100
	}
	if c.GatecrasherIssuer == "" {
		c.GatecrasherIssuer = "gatecrasher"
	}
}

// Service is Warden's operations over the store.
type Service struct {
	st       *store.Store
	keys     *issuer.KeyStore
	rules    *policy.Rules
	approver approval.Approver
	decide   approval.Verifier
	cfg      Config
	now      func() time.Time

	// Deny is the in-process deny-list mirror, kept current after every revocation (the auth module's
	// verifier and Warden's own exchange read it).
	Deny *libauth.DenyList

	denyMu   sync.Mutex
	denyBody []byte
	denyETag string
}

// Options builds a Service.
type Options struct {
	Store    *store.Store
	Keys     *issuer.KeyStore
	Rules    *policy.Rules
	Approver approval.Approver
	// DecisionKeys verifies Gatecrasher's signed decisions.
	DecisionKeys approval.KeySet
	Config       Config
	Now          func() time.Time
	// Deny is the deny-list the service keeps current; pass the one the auth module's verifier reads
	// (auth.UseDenyList). Nil makes a private one.
	Deny *libauth.DenyList
}

// New builds the service and loads the deny-list.
func New(ctx context.Context, o Options) (*Service, error) {
	if o.Store == nil || o.Keys == nil || o.Rules == nil {
		return nil, errors.New("service: store, keys and rules are required")
	}
	o.Config.defaults()
	now := o.Now
	if now == nil {
		now = time.Now
	}
	s := &Service{st: o.Store, keys: o.Keys, rules: o.Rules, approver: o.Approver, cfg: o.Config, now: now,
		decide: approval.Verifier{Keys: o.DecisionKeys, Now: now}, Deny: o.Deny}
	if s.Deny == nil {
		s.Deny = libauth.NewDenyList()
	}
	return s, s.reloadDeny(ctx)
}

// Issuer is the iss of Warden's tokens.
func (s *Service) Issuer() string { return s.cfg.Issuer }

// Keys is the signing key store.
func (s *Service) Keys() *issuer.KeyStore { return s.keys }

// Config is the effective configuration.
func (s *Service) Config() Config { return s.cfg }

// Caller is a verified caller, projected from the guard's principal.
type Caller struct {
	Sub    string
	Kind   string
	Scopes []string
	// Admin is the owner (scope "*") or a holder of warden.admin.
	Admin bool
	// Human is the owner signed in through the identity module (or an owner API key).
	Human bool
}

// CallerFrom projects a libs auth principal. The identity module's owner and API keys carry ids
// "user:<id>" and "key:<id>"; Warden-issued tokens carry the principal's sub and kind.
func CallerFrom(p libauth.Principal) (Caller, bool) {
	if !p.Verified || strings.TrimSpace(p.ID) == "" {
		return Caller{}, false
	}
	c := Caller{Sub: p.ID, Kind: p.Kind, Scopes: append([]string(nil), p.Scopes...)}
	c.Admin = slices.Contains(p.Scopes, "*") || slices.Contains(p.Scopes, "warden.admin")
	if !ValidKind(p.Kind) {
		// An identity-module principal: the owner's session or one of the owner's API keys.
		c.Kind = KindHuman
		c.Human = strings.HasPrefix(p.ID, "user:") || c.Admin
	}
	c.Human = c.Human || p.Kind == KindHuman
	return c, true
}

// Errors with a stable meaning for transports.
var (
	ErrInvalid   = errors.New("invalid request")
	ErrForbidden = errors.New("forbidden")
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("conflict")
	// ErrInvalidGrant is a refused parent credential, device code or subject token (OAuth invalid_grant).
	ErrInvalidGrant = errors.New("invalid_grant")
	// ErrInvalidScope is a scope or audience outside every grant (OAuth invalid_scope / invalid_target).
	ErrInvalidScope = errors.New("invalid_scope")
	// Device flow states (RFC 8628 §3.5).
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
	ErrAccessDenied         = errors.New("access_denied")
	ErrExpiredToken         = errors.New("expired_token")
	ErrUnavailable          = errors.New("temporarily_unavailable")
)

// Describe is err's message without its sentinel prefix, for an error_description or an API message.
func Describe(err error) string {
	msg := err.Error()
	for _, base := range []error{ErrInvalid, ErrForbidden, ErrNotFound, ErrConflict, ErrInvalidGrant, ErrInvalidScope, ErrUnavailable} {
		if errors.Is(err, base) {
			if rest, ok := strings.CutPrefix(msg, base.Error()+": "); ok {
				return rest
			}
		}
	}
	return msg
}

func wrap(base error, format string, a ...any) error {
	return fmt.Errorf("%w: %s", base, fmt.Sprintf(format, a...))
}

var subRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:/._@+-]{0,255}$`)

// ValidSub reports whether sub can name a principal (a Registry canonical id).
func ValidSub(sub string) bool { return subRe.MatchString(sub) && !strings.Contains(sub, "..") }

// timeFmt is fixed width, so stored times compare as strings.
const timeFmt = "2006-01-02T15:04:05.000000Z"

func ts(t time.Time) string { return t.UTC().Format(timeFmt) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(timeFmt, s)
	return t
}

func nullTS(n sql.NullString) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return parseTS(n.String)
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func newID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b)
}

// Secret prefixes. They make a leaked value recognizable to scanners and tell credential kinds apart.
const (
	parentPrefix = "wdn_p_"
	pollPrefix   = "wdn_e_"
	devicePrefix = "wdn_d_"
)

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func mustJSON(v any) string {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return "{}"
	}
	return string(b)
}

// audit writes one audit row inside tx. detail must hold no secret.
func (s *Service) audit(ctx context.Context, tx store.Querier, actor, action, subject string, detail any) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit (at, actor, action, subject, detail) VALUES (?, ?, ?, ?, ?)`,
		ts(s.now()), actor, action, subject, mustJSON(detail))
	return err
}

// policyAudit is the libs policy AuditSink: every tier decision becomes an audit row.
type policyAudit struct{ s *Service }

func (a policyAudit) Record(ctx context.Context, e libpolicy.AuditEvent) error {
	var rules []string
	for _, m := range e.Decision.MatchedPolicies {
		rules = append(rules, m.ID)
	}
	return a.s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		return a.s.audit(ctx, tx, e.Principal.URN, "policy.evaluate", e.Resource.ID, map[string]any{
			"action": e.Action, "effect": e.Decision.Effect, "admission": e.ProposedAdmission, "rules": rules,
			"mode": e.Mode, "failure": e.Failure})
	})
}

// classify runs the PDP through libs policy's evaluator (enforce, fail closed, audited).
func (s *Service) classify(ctx context.Context, requestID string, f policy.Facts) (policy.Verdict, error) {
	ev := libpolicy.Evaluator{PDP: policy.PDP{Rules: s.rules}, Audit: policyAudit{s}}
	actor := f.Requester
	if actor == "" {
		actor = f.Principal
	}
	req := libpolicy.Request{RequestID: requestID, Principal: libpolicy.Principal{URN: "warden:" + urnEscape(actor), Kind: f.Kind},
		Action: "warden." + string(f.Action), Resource: libpolicy.Resource{Type: "warden.request", ID: requestID},
		Scope: "warden", Context: map[string]any{policy.FactsKey: f}}
	res, err := ev.Evaluate(ctx, req, libpolicy.Options{Mode: libpolicy.Enforce, FailMode: libpolicy.FailClosed})
	if err != nil {
		return policy.Verdict{}, fmt.Errorf("%w: policy unavailable", ErrUnavailable)
	}
	v := s.rules.Classify(f) // same pure function the PDP ran; gives the rule id and approver class
	if policy.TierOf(res.Decision) != v.Tier {
		return policy.Verdict{}, fmt.Errorf("%w: policy result mismatch", ErrUnavailable)
	}
	return v, nil
}

func urnEscape(s string) string {
	r := strings.NewReplacer(" ", "%20", "#", "%23", "?", "%3F")
	return r.Replace(s)
}
