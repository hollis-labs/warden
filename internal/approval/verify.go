package approval

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// KeySet resolves a decision signing key by kid.
type KeySet interface {
	Key(ctx context.Context, kid string) (ed25519.PublicKey, error)
}

// StaticKeys is a fixed key set (tests, the fake, a pinned key file).
type StaticKeys map[string]ed25519.PublicKey

// Key implements KeySet.
func (s StaticKeys) Key(_ context.Context, kid string) (ed25519.PublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return nil, ErrDecision
}

// ParseJWKS reads an OKP/Ed25519 JWKS document.
func ParseJWKS(b []byte) (StaticKeys, error) {
	var doc struct {
		Keys []struct {
			Kty, Crv, Kid, X string
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	out := StaticKeys{}
	for _, k := range doc.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		out[k.Kid] = ed25519.PublicKey(x)
	}
	return out, nil
}

// LoadJWKSFile reads a pinned JWKS file.
func LoadJWKSFile(path string) (StaticKeys, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: an operator-configured path
	if err != nil {
		return nil, err
	}
	return ParseJWKS(b)
}

// RemoteKeys fetches Gatecrasher's JWKS, caches it, and refetches on an unknown kid at most once a second.
type RemoteKeys struct {
	URL    string
	Client *http.Client
	// Token, when set, is the bearer for the JWKS read (Gatecrasher serves it under gatecrasher.approval.read).
	Token func(ctx context.Context) (string, error)

	mu      sync.Mutex
	keys    StaticKeys
	fetched time.Time
}

// Key implements KeySet.
func (r *RemoteKeys) Key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.keys[kid]; ok && time.Since(r.fetched) < time.Hour {
		return k, nil
	}
	if time.Since(r.fetched) < time.Second {
		return nil, ErrDecision
	}
	c := r.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return nil, err
	}
	if r.Token != nil {
		tok, terr := r.Token(ctx)
		if terr != nil {
			return nil, fmt.Errorf("approval: credential: %w", terr)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.Do(req) //nolint:gosec // G704: the operator-configured Gatecrasher JWKS URL
	if err != nil {
		return nil, fmt.Errorf("approval: fetch decision keys: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("approval: fetch decision keys: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	keys, err := ParseJWKS(b)
	if err != nil {
		return nil, err
	}
	r.keys, r.fetched = keys, time.Now()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, ErrDecision
}

// Expect is what the decision must match: what Warden asked and who may not decide.
type Expect struct {
	Issuer     string // Gatecrasher's iss (default "gatecrasher")
	ApprovalID string
	RequestID  string
	Digest     string
	Tier       string
	Requested  Requested
	// NotDeciders may not decide their own request (the principal and the requester).
	NotDeciders []string
	// Owner, when set, is the only principal that may decide a critical request.
	Owner string
}

// Verifier checks signed decisions.
type Verifier struct {
	Keys KeySet
	Now  func() time.Time
}

// MaxDecisionLife bounds how long a decision may be redeemed after it is made.
const MaxDecisionLife = 10 * time.Minute

// Verify checks jws and returns the decision. Every mismatch is ErrDecision with a reason for the log.
func (v Verifier) Verify(ctx context.Context, jws string, want Expect) (Decision, error) {
	bad := func(why string) (Decision, error) { return Decision{}, fmt.Errorf("%w: %s", ErrDecision, why) }
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || v.Keys == nil {
		return bad("malformed")
	}
	enc := base64.RawURLEncoding
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return bad("header")
	}
	var hdr struct{ Alg, Kid string }
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "EdDSA" || hdr.Kid == "" {
		return bad("algorithm")
	}
	pub, err := v.Keys.Key(ctx, hdr.Kid)
	if err != nil {
		if errors.Is(err, ErrDecision) {
			return bad("unknown key")
		}
		return Decision{}, err // unavailable, not refused: the caller retries
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return bad("signature")
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return bad("payload")
	}
	var d Decision
	if json.Unmarshal(pb, &d) != nil {
		return bad("payload")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	iss := want.Issuer
	if iss == "" {
		iss = "gatecrasher"
	}
	switch {
	case d.Iss != iss:
		return bad("issuer")
	case d.Aud != "warden":
		return bad("audience")
	case d.ApprovalID != want.ApprovalID || d.RequestID != want.RequestID:
		return bad("bound to another approval")
	case d.RequestDigest != want.Digest:
		return bad("bound to a different request")
	case d.Tier != want.Tier:
		return bad("tier")
	case d.Outcome != Approved && d.Outcome != Denied:
		return bad("outcome")
	case d.Exp == 0 || !now.Before(time.Unix(d.Exp, 0)):
		return bad("expired")
	case time.Unix(d.Exp, 0).Sub(d.DecidedAt) > MaxDecisionLife+time.Minute:
		return bad("lives too long")
	case d.Decider.Sub == "" || slices.Contains(want.NotDeciders, d.Decider.Sub):
		return bad("self-approval")
	}
	switch want.Tier {
	case "critical":
		if d.Decider.Kind != "human" || (want.Owner != "" && d.Decider.Sub != want.Owner) {
			return bad("critical needs the owner")
		}
	case "elevated":
		if d.Decider.Kind != "human" && d.Decider.Kind != "agent" {
			return bad("decider kind")
		}
	default:
		return bad("tier")
	}
	if n := d.Narrowed; n != nil && d.Outcome == Approved {
		for _, s := range n.Scopes {
			if !slices.Contains(want.Requested.Scopes, s) {
				return bad("narrowed scopes widen the request")
			}
		}
		if n.TTLSeconds < 0 || (want.Requested.TTLSeconds > 0 && n.TTLSeconds > want.Requested.TTLSeconds) {
			return bad("narrowed ttl widens the request")
		}
	}
	return d, nil
}
