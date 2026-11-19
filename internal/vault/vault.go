// Package vault is the skeleton of Warden's secret store (milestone 2 fills it in). It fixes the shapes now:
// warden:// references, envelope encryption (a fresh data key per secret, wrapped by a key-encryption key),
// the storage Backend that a Postgres table or OpenBao can implement, leases, and the write-only intake a
// request_secret card posts to.
//
// What a caller ever holds is a Ref, a Lease or a short-lived token: never the KEK, never a DEK, and never
// a value it did not ask to receive under a grant.
package vault

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Scheme is the reference scheme (owner ruling 2026-11-19: warden://, not hollis://).
const Scheme = "warden"

var segRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Ref names a secret: warden://<scope>/<name>[/<name>...], e.g. warden://llm-gateway/anthropic. Scope is an
// app id or a namespace; names are lowercase path segments.
type Ref struct {
	Scope string
	Path  []string
}

// ParseRef parses and validates a reference.
func ParseRef(s string) (Ref, error) {
	rest, ok := strings.CutPrefix(s, Scheme+"://")
	if !ok {
		return Ref{}, fmt.Errorf("vault: reference must start with %s://", Scheme)
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || len(parts) > 6 {
		return Ref{}, errors.New("vault: reference is warden://<scope>/<name>")
	}
	for _, p := range parts {
		if !segRe.MatchString(p) {
			return Ref{}, fmt.Errorf("vault: invalid reference segment %q", p)
		}
	}
	return Ref{Scope: parts[0], Path: parts[1:]}, nil
}

// String renders the reference.
func (r Ref) String() string { return Scheme + "://" + r.Scope + "/" + strings.Join(r.Path, "/") }

// Kind is what a secret is, which decides how it may be delivered.
type Kind string

const (
	KindAPIKey       Kind = "api_key"
	KindOAuthClient  Kind = "oauth_client"
	KindRefreshToken Kind = "refresh_token"
	KindPassword     Kind = "password"
	KindPrivateKey   Kind = "private_key"
	KindWebhook      Kind = "webhook_secret"
)

// Delivery is how a value reaches its user, in order of preference (design §6).
type Delivery string

const (
	Brokered Delivery = "brokered" // a gateway substitutes it server-side; the caller never sees it
	Dynamic  Delivery = "dynamic"  // Warden mints a short-lived derived credential
	RawLease Delivery = "raw"      // the value, leased, injected at process start
)

// Metadata describes a stored secret. It is safe to list.
type Metadata struct {
	Ref       Ref
	Kind      Kind
	Delivery  []Delivery // allowed deliveries
	Owner     string     // the sub that owns it (an app, or the human owner)
	Version   int
	CreatedAt time.Time
	RotatedAt time.Time
	ExpiresAt time.Time // zero when the vendor key does not expire; drives age alerts
}

// Record is a stored secret: metadata and the sealed value. Backends store Records and never see plaintext.
type Record struct {
	Metadata
	Sealed Sealed
}

// Backend is the storage contract (Postgres table first; OpenBao could implement it later).
type Backend interface {
	Put(ctx context.Context, r Record) error // a new version; Version is assigned by the backend
	Get(ctx context.Context, ref Ref) (Record, error)
	Metadata(ctx context.Context, scope string) ([]Metadata, error)
	Delete(ctx context.Context, ref Ref) error
}

// ErrNotFound is a reference with no secret.
var ErrNotFound = errors.New("vault: no such secret")

// Lease is a granted use of a secret: who, which, until when, and the audit id. The value travels only
// inside a delivery, never inside a Lease.
type Lease struct {
	ID        string
	Ref       Ref
	Holder    string // sub
	Grant     string // grant id that allowed it
	Delivery  Delivery
	ExpiresAt time.Time
}

// Intake is a one-use, write-only slot for request_secret: Gatecrasher's card form POSTs the value straight
// to Warden at the intake URL. Gatecrasher and any model transcript never carry the value.
type Intake struct {
	ID        string
	Ref       Ref    // where the value will be stored
	Requester string // the sub that asked
	Kind      Kind
	ExpiresAt time.Time
}

// Store is the vault service a milestone-2 Warden exposes. Milestone 1 ships the Sealer and a memory
// Backend; the methods below are the interface the API and the warden:// secrets backend will call.
type Store interface {
	Put(ctx context.Context, owner string, ref Ref, kind Kind, delivery []Delivery, value []byte) (Metadata, error)
	Lease(ctx context.Context, holder, grant string, ref Ref, d Delivery, ttl time.Duration) (Lease, []byte, error)
	OpenIntake(ctx context.Context, requester string, ref Ref, kind Kind, ttl time.Duration) (Intake, error)
	FillIntake(ctx context.Context, intakeID string, value []byte) (Metadata, error)
}
