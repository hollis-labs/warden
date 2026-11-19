package approval_test

import (
	"encoding/json"
	"testing"

	"github.com/hollis-labs/warden/internal/approval"
)

// The vectors were computed by Gatecrasher's own pkg/approvalapi.RequestDigest (gatecrasher main, 2026-11-19).
// If this test fails, Gatecrasher refuses every submit: its server recomputes and checks the digest.
func TestDigestMatchesGatecrasher(t *testing.T) {
	p := approval.PrincipalRef{Sub: "app:surface", Kind: "app", Act: []approval.Party{{Sub: "agent:lead", Kind: "agent"}}}
	r := approval.Requested{Audience: "llm-gateway", Scopes: []string{"llm-gateway.decide", "llm-gateway.embed"}, TTLSeconds: 2592000,
		Constraints: map[string]any{"models": []any{"claude-haiku-5-5"}, "budget_usd": 5, "note": "é<>&"}}
	if got, want := approval.Digest(p, r, "elevated"), "sha256:bc57ace2efdb264a32c405593334da00e4ca36d6485fb48836bd71dda8395246"; got != want {
		t.Errorf("vector 1: %s, want %s", got, want)
	}
	got := approval.Digest(approval.PrincipalRef{Sub: "agent:x", Kind: "agent"}, approval.Requested{Audience: "warden", TTLSeconds: 1}, "critical")
	if want := "sha256:72f8dc5bca24f8f756a679bd10f3672a7cc9c9d7dc0564b82af7ef073d751b04"; got != want {
		t.Errorf("vector 2 (nil scopes and constraints): %s, want %s", got, want)
	}
}

// The submit body has exactly Gatecrasher's field set (its decoder refuses unknown fields).
func TestSubmitShape(t *testing.T) {
	b, _ := json.Marshal(approval.Request{IdempotencyKey: "req_1", Source: "warden", Kind: "credential_grant", Tier: "elevated",
		ApproverClass: "approve.enroll", Principal: approval.PrincipalRef{Sub: "app:a", Kind: "app"},
		Requested: approval.Requested{Audience: "warden", Scopes: []string{"warden.read"}, TTLSeconds: 60},
		Evidence:  approval.Evidence{TaskID: "T-1", PolicyRule: "enroll-workload"}, RequestDigest: "sha256:00"})
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"idempotency_key", "source", "kind", "tier", "approver_class", "principal", "requested", "purpose", "evidence", "request_digest", "expires_at"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %s", k)
		}
		delete(m, k)
	}
	if len(m) != 0 {
		t.Errorf("fields Gatecrasher does not know: %v", m)
	}
}
