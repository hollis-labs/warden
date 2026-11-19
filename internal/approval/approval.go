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
	"sort"
	"time"
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

// Party is a principal on the wire.
type Party struct {
	Sub  string `json:"sub"`
	Kind string `json:"kind"`
}

// PrincipalRef is the principal a credential is for, with the actor chain that asked.
type PrincipalRef struct {
	Sub  string  `json:"sub"`
	Kind string  `json:"kind"`
	Act  []Party `json:"act,omitempty"`
}

// Requested is the grant being asked for.
type Requested struct {
	Action      string         `json:"action"` // grant, enroll, device
	Audience    string         `json:"audience,omitempty"`
	Scopes      []string       `json:"scopes,omitempty"`
	TTLSeconds  int64          `json:"ttl_seconds,omitempty"`
	Constraints map[string]any `json:"constraints,omitempty"`
}

// Request is what Warden submits.
type Request struct {
	IdempotencyKey string            `json:"idempotency_key"` // the Warden request id
	Source         string            `json:"source"`          // always "warden"
	Kind           string            `json:"kind"`            // "credential_grant"
	Tier           string            `json:"tier"`            // elevated or critical
	ApproverClass  string            `json:"approver_class,omitempty"`
	Principal      PrincipalRef      `json:"principal"`
	Requested      Requested         `json:"requested"`
	Purpose        string            `json:"purpose,omitempty"`
	Evidence       map[string]string `json:"evidence,omitempty"`
	RequestDigest  string            `json:"request_digest"`
	ExpiresAt      time.Time         `json:"expires_at"`
}

// Digest binds a decision to exactly what was asked: sha256 over a canonical JSON of the principal, the
// requested grant and the tier. The encoding is canonical for these types (fixed field order, sorted
// scopes, no floats, Go's sorted map keys); constraints hold only strings, integers, booleans and lists of
// them, for which encoding/json and RFC 8785 agree.
func Digest(p PrincipalRef, r Requested, tier string) string {
	r.Scopes = append([]string(nil), r.Scopes...)
	sort.Strings(r.Scopes)
	b, _ := json.Marshal(struct {
		Principal PrincipalRef `json:"principal"`
		Requested Requested    `json:"requested"`
		Tier      string       `json:"tier"`
	}{p, r, tier})
	sum := sha256.Sum256(b)
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
