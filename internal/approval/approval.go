// Package approval is Warden's side of the Gatecrasher approval contract. Warden never renders or
// collects an approval itself: it submits an approval request (tier, principal, requested grant,
// evidence), polls or awaits its status, and accepts only a decision Gatecrasher signed. This package
// holds the wire types, the Approver interface, the signed-decision verifier, an HTTP client and an
// in-process fake for development and tests.
//
// Contract v0 (proposed to the Gatecrasher builder 2026-11-19; docs/gatecrasher-contract.md):
//
//	POST /api/gate/v1/approvals                 submit (idempotent on idempotency_key)
//	GET  /api/gate/v1/approvals/{id}            status
//	GET  /api/gate/v1/approvals/{id}/await      long-poll status (?timeout=30s)
//	POST /api/gate/v1/approvals/{id}/withdraw   withdraw
package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Status of an approval in Gatecrasher.
type Status string

const (
	Pending   Status = "pending"
	Approved  Status = "approved"
	Denied    Status = "denied"
	Expired   Status = "expired"
	Withdrawn Status = "withdrawn"
)

// Terminal reports whether s will not change again.
func (s Status) Terminal() bool { return s != Pending }

// Party is a principal on the wire (Gatecrasher approvalapi.Actor).
type Party struct {
	Sub  string `json:"sub"`
	Kind string `json:"kind"`
}

// PrincipalRef is the principal a credential is for, with the actor chain that asked (outermost first).
type PrincipalRef struct {
	Sub  string  `json:"sub"`
	Kind string  `json:"kind"`
	Act  []Party `json:"act,omitempty"`
}

// Requested is the exact grant asked for (Gatecrasher approvalapi.Requested). Every field is always
// encoded: constraints as an object, scopes as an array.
type Requested struct {
	Audience    string         `json:"audience"`
	Scopes      []string       `json:"scopes"`
	TTLSeconds  int64          `json:"ttl_seconds"`
	Constraints map[string]any `json:"constraints"`
}

// Evidence links a request to what prompted it.
type Evidence struct {
	TaskID     string `json:"task_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	PolicyRule string `json:"policy_rule,omitempty"`
}

// Request is what Warden submits.
type Request struct {
	IdempotencyKey string       `json:"idempotency_key"` // the Warden request id
	Source         string       `json:"source"`          // always "warden"
	Kind           string       `json:"kind"`            // "credential_grant"
	Tier           string       `json:"tier"`            // elevated or critical
	ApproverClass  string       `json:"approver_class,omitempty"`
	Principal      PrincipalRef `json:"principal"`
	Requested      Requested    `json:"requested"`
	Purpose        string       `json:"purpose"`
	Evidence       Evidence     `json:"evidence"`
	RequestDigest  string       `json:"request_digest"`
	ExpiresAt      time.Time    `json:"expires_at"`
}

// Digest binds a decision to exactly what was asked: "sha256:" and the hex SHA-256 of the RFC 8785 (JCS)
// canonical JSON of {"principal", "requested", "tier"}, encoded as these types encode them (act omitted
// when empty, constraints always an object, scopes always an array). It matches Gatecrasher's
// approvalapi.RequestDigest byte for byte (TestDigestMatchesGatecrasher).
func Digest(p PrincipalRef, r Requested, tier string) string {
	if r.Constraints == nil {
		r.Constraints = map[string]any{}
	}
	if r.Scopes == nil {
		r.Scopes = []string{}
	}
	b, err := json.Marshal(struct {
		Principal PrincipalRef `json:"principal"`
		Requested Requested    `json:"requested"`
		Tier      string       `json:"tier"`
	}{p, r, tier})
	if err != nil {
		return ""
	}
	canon, err := jsoncanonicalizer.Transform(b)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Ticket is Gatecrasher's answer to a submit or a status read.
type Ticket struct {
	ApprovalID string `json:"approval_id"`
	Status     Status `json:"status"`
	// Decision is the compact JWS, present once approved or denied.
	Decision string `json:"decision,omitempty"`
}

// Approver is the Gatecrasher client Warden uses.
type Approver interface {
	Submit(ctx context.Context, r Request) (Ticket, error)
	// Await returns the current ticket, waiting up to wait for a change from pending (0 = no wait).
	Await(ctx context.Context, approvalID string, wait time.Duration) (Ticket, error)
	Withdraw(ctx context.Context, approvalID string) error
}

// Narrowed is what an approver may cut down; it can only narrow.
type Narrowed struct {
	Scopes     []string `json:"scopes,omitempty"`
	TTLSeconds int64    `json:"ttl_seconds,omitempty"`
}

// Decision is the verified payload of a signed decision.
type Decision struct {
	Iss           string    `json:"iss"`
	Aud           string    `json:"aud"`
	JTI           string    `json:"jti,omitempty"`
	Iat           int64     `json:"iat,omitempty"`
	ApprovalID    string    `json:"approval_id"`
	RequestID     string    `json:"request_id"`
	RequestDigest string    `json:"request_digest"`
	Outcome       Status    `json:"outcome"` // approved or denied
	Tier          string    `json:"tier"`
	Decider       Party     `json:"decider"`
	DecidedAt     time.Time `json:"decided_at"`
	Exp           int64     `json:"exp"`
	Narrowed      *Narrowed `json:"narrowed,omitempty"`
}

// ErrDecision is a decision Warden refuses to act on.
var ErrDecision = errors.New("approval: decision does not verify")
