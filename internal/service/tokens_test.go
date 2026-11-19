package service_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	libauth "github.com/hollis-labs/libs/security/auth"

	"github.com/hollis-labs/warden/internal/service"
)

// The worked example (design §7): the Surface classifier asks for llm-gateway decide+embed, policy puts it
// in ground tier, and its parent credential then mints a 60-minute, single-audience token with a grant claim.
func TestPilotSurfaceClassifier(t *testing.T) {
	h := newHarness(t)
	parent := h.enroll("app:surface", service.KindApp)
	r := h.grant("app:surface", service.KindApp, "llm-gateway", "llm-gateway.decide", "llm-gateway.embed")
	if r.Tier != "ground" || r.Rule != "llm-gateway-use" {
		t.Fatalf("tier %s rule %s, want ground / llm-gateway-use", r.Tier, r.Rule)
	}
	tok := h.refresh(parent, "llm-gateway")
	if tok.Audience != "llm-gateway" || tok.Scope != "llm-gateway.decide llm-gateway.embed" || tok.Grant != r.GrantID {
		t.Fatalf("token %+v", tok)
	}
	if tok.TTL != 3600 {
		t.Fatalf("app token ttl %d, want 3600", tok.TTL)
	}
	if tok.RefreshToken == "" || tok.RefreshToken == parent {
		t.Fatal("refresh must rotate the parent credential")
	}
	c, err := h.svc.VerifyOwn(tok.AccessToken, "llm-gateway")
	if err != nil || c.Grant != r.GrantID || c.Kind != service.KindApp || c.Sub != "app:surface" || c.SID == "" {
		t.Fatalf("claims %+v err %v", c, err)
	}
}

func TestAccessTTLByKind(t *testing.T) {
	h := newHarness(t)
	for kind, want := range map[string]int{service.KindAgent: 900, service.KindApp: 3600, service.KindMachine: 3600} {
		sub := kind + ":ttl"
		p := h.enroll(sub, kind)
		tok := h.refresh(p, "warden")
		if tok.TTL != want {
			t.Errorf("%s: ttl %d, want %d", kind, tok.TTL, want)
		}
		// A shorter requested TTL is honored; a longer one is capped.
		tok2, err := h.svc.Refresh(h.ctx, tok.RefreshToken, service.MintRequest{Audience: "warden", TTL: 2 * time.Minute})
		if err != nil || tok2.TTL != 120 {
			t.Errorf("%s: short ttl %d err %v", kind, tok2.TTL, err)
		}
		tok3, err := h.svc.Refresh(h.ctx, tok2.RefreshToken, service.MintRequest{Audience: "warden", TTL: 10 * time.Hour})
		if err != nil || tok3.TTL != want {
			t.Errorf("%s: long ttl %d err %v", kind, tok3.TTL, err)
		}
	}
}

func TestScopesNarrowOnly(t *testing.T) {
	h := newHarness(t)
	p := h.enroll("agent:a", service.KindAgent)
	h.grant("agent:a", service.KindAgent, "llm-gateway", "llm-gateway.chat", "llm-gateway.decide")

	// A subset of the grant: fine.
	tok := h.refresh(p, "llm-gateway", "llm-gateway.chat")
	if tok.Scope != "llm-gateway.chat" {
		t.Fatalf("scope %q", tok.Scope)
	}
	// Beyond the grant: refused, and the parent is NOT consumed by a refused mint.
	_, err := h.svc.Refresh(h.ctx, tok.RefreshToken, service.MintRequest{Audience: "llm-gateway", Scopes: []string{"llm-gateway.embed"}})
	wantErr(t, err, service.ErrInvalidScope, "scope beyond grant")
	tok = h.refresh(tok.RefreshToken, "llm-gateway") // still usable
	// A scope of another audience: refused.
	_, err = h.svc.Refresh(h.ctx, tok.RefreshToken, service.MintRequest{Audience: "llm-gateway", Scopes: []string{"tesseract.read"}})
	wantErr(t, err, service.ErrInvalidScope, "foreign scope")
	// Wildcards are never issued.
	_, err = h.svc.Refresh(h.ctx, tok.RefreshToken, service.MintRequest{Audience: "llm-gateway", Scopes: []string{"llm-gateway.*"}})
	wantErr(t, err, service.ErrInvalidScope, "wildcard")

	// Exchange, same audience: narrowing works, widening does not.
	narrow, err := h.svc.Exchange(h.ctx, service.ExchangeRequest{SubjectToken: tok.AccessToken, MintRequest: service.MintRequest{Scopes: []string{"llm-gateway.decide"}}})
	if err != nil || narrow.Scope != "llm-gateway.decide" || narrow.Audience != "llm-gateway" {
		t.Fatalf("narrowing exchange: %+v %v", narrow, err)
	}
	_, err = h.svc.Exchange(h.ctx, service.ExchangeRequest{SubjectToken: narrow.AccessToken, MintRequest: service.MintRequest{Scopes: []string{"llm-gateway.chat"}}})
	wantErr(t, err, service.ErrInvalidScope, "widening exchange")
	if narrow.RefreshToken != "" {
		t.Fatal("exchange must not hand out a parent credential")
	}
}

func TestAudienceBoundToGrant(t *testing.T) {
	h := newHarness(t)
	p := h.enroll("agent:b", service.KindAgent)
	h.grant("agent:b", service.KindAgent, "llm-gateway", "llm-gateway.chat")
	// No grant for tesseract: no token for tesseract.
	_, err := h.svc.Refresh(h.ctx, p, service.MintRequest{Audience: "tesseract"})
	wantErr(t, err, service.ErrInvalidScope, "audience without a grant")

	llm := h.refresh(p, "llm-gateway")
	w := h.refresh(llm.RefreshToken, "warden")
	// A resource server holding an llm-gateway token cannot exchange it for another audience.
	_, err = h.svc.Exchange(h.ctx, service.ExchangeRequest{SubjectToken: llm.AccessToken, MintRequest: service.MintRequest{Audience: "warden"}})
	wantErr(t, err, service.ErrInvalidScope, "cross-audience from a resource token")
	// A Warden token can be exchanged for an audience the principal holds a grant on, and only that.
	x, err := h.svc.Exchange(h.ctx, service.ExchangeRequest{SubjectToken: w.AccessToken, MintRequest: service.MintRequest{Audience: "llm-gateway"}})
	if err != nil || x.Audience != "llm-gateway" {
		t.Fatalf("cross-audience from a warden token: %+v %v", x, err)
	}
	_, err = h.svc.Exchange(h.ctx, service.ExchangeRequest{SubjectToken: w.AccessToken, MintRequest: service.MintRequest{Audience: "tesseract"}})
	wantErr(t, err, service.ErrInvalidScope, "cross-audience without a grant")
	// The token carries exactly one audience on the wire.
	var claims map[string]any
	payload := strings.Split(x.AccessToken, ".")[1]
	b, _ := base64URL(payload)
	_ = json.Unmarshal(b, &claims)
	if aud, ok := claims["aud"].(string); !ok || aud != "llm-gateway" {
		t.Fatalf("aud claim %#v, want the single string llm-gateway", claims["aud"])
	}
}

func TestRotationAndReuseDetection(t *testing.T) {
	h := newHarness(t)
	p0 := h.enroll("app:rot", service.KindApp)
	t1 := h.refresh(p0, "warden")
	t2 := h.refresh(t1.RefreshToken, "warden")
	p2 := t2.RefreshToken

	// Replaying the first (rotated) parent is reuse: refused, and the whole family is revoked.
	_, err := h.svc.Refresh(h.ctx, p0, service.MintRequest{Audience: "warden"})
	wantErr(t, err, service.ErrInvalidGrant, "replayed parent")
	if !strings.Contains(err.Error(), "reuse") {
		t.Fatalf("error should name reuse: %v", err)
	}
	// The newest parent of the family no longer works either.
	_, err = h.svc.Refresh(h.ctx, p2, service.MintRequest{Audience: "warden"})
	wantErr(t, err, service.ErrInvalidGrant, "newest parent after reuse")
	// And every token the family minted is denied, locally and on the published deny-list.
	for _, tok := range []service.Token{t1, t2} {
		if _, err := h.svc.VerifyOwn(tok.AccessToken, ""); err == nil {
			t.Fatal("a token minted by a revoked family still verifies")
		}
	}
	body, _ := h.svc.DenyListDoc()
	var doc libauth.DenyListDoc
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.SID) != 1 {
		t.Fatalf("deny-list %s: %v", body, err)
	}
	c, _ := h.svc.Keys().Verify(t1.AccessToken, iss, h.clock.Now())
	if doc.SID[0] != c.SID {
		t.Fatalf("deny-list sid %v, want the family %s", doc.SID, c.SID)
	}
	// The family is listed as revoked for reuse.
	fams, _ := h.svc.ListFamilies(h.ctx, h.owner, "app:rot")
	if len(fams) != 1 || fams[0].RevokedAt.IsZero() || fams[0].Reason != "reuse detected" {
		t.Fatalf("families %+v", fams)
	}
	// A second enrollment of the same principal is a new family (re-enrollment is critical; the owner does it).
	h.enroll("app:rot", service.KindApp)
}

func TestExpiry(t *testing.T) {
	h := newHarness(t)
	p := h.enroll("agent:exp", service.KindAgent)
	tok := h.refresh(p, "warden")
	h.clock.Add(15*time.Minute + 31*time.Second) // past exp plus leeway
	if _, err := h.svc.VerifyOwn(tok.AccessToken, ""); err == nil {
		t.Fatal("an expired token verifies")
	}
	// The parent goes idle after 30 days without use.
	h.clock.Add(31 * 24 * time.Hour)
	_, err := h.svc.Refresh(h.ctx, tok.RefreshToken, service.MintRequest{Audience: "warden"})
	wantErr(t, err, service.ErrInvalidGrant, "idle parent")
}

func TestGrantExpiryBoundsTokens(t *testing.T) {
	h := newHarness(t)
	p := h.enroll("app:short", service.KindApp)
	_, err := h.svc.CreateRequest(h.ctx, as("app:short", service.KindApp),
		service.RequestInput{Audience: "llm-gateway", Scopes: []string{"llm-gateway.chat"}, TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	tok := h.refresh(p, "llm-gateway")
	if tok.TTL > 600 {
		t.Fatalf("token outlives its grant: ttl %d", tok.TTL)
	}
	h.clock.Add(11 * time.Minute)
	_, err = h.svc.Refresh(h.ctx, tok.RefreshToken, service.MintRequest{Audience: "llm-gateway"})
	wantErr(t, err, service.ErrInvalidScope, "expired grant")
}

func TestRevokeGrant(t *testing.T) {
	h := newHarness(t)
	p := h.enroll("agent:rev", service.KindAgent)
	r := h.grant("agent:rev", service.KindAgent, "llm-gateway", "llm-gateway.chat")
	tok := h.refresh(p, "llm-gateway")
	if _, err := h.svc.RevokeGrant(h.ctx, as("agent:other", service.KindAgent), r.GrantID, ""); err == nil {
		t.Fatal("another principal revoked my grant")
	}
	g, err := h.svc.RevokeGrant(h.ctx, as("agent:rev", service.KindAgent), r.GrantID, "done with it")
	if err != nil || g.RevokedAt.IsZero() {
		t.Fatalf("revoke: %+v %v", g, err)
	}
	if _, err = h.svc.VerifyOwn(tok.AccessToken, ""); err == nil {
		t.Fatal("a token of a revoked grant still verifies")
	}
	body, _ := h.svc.DenyListDoc()
	var doc libauth.DenyListDoc
	_ = json.Unmarshal(body, &doc)
	if !slices.Contains(doc.JTI, tok.JTI) {
		t.Fatalf("published deny-list %s lacks the revoked grant's token %s", body, tok.JTI)
	}
	_, err = h.svc.Refresh(h.ctx, tok.RefreshToken, service.MintRequest{Audience: "llm-gateway"})
	wantErr(t, err, service.ErrInvalidScope, "mint from a revoked grant")
	// Exchanging a token of the revoked grant is refused too.
	_, err = h.svc.Exchange(h.ctx, service.ExchangeRequest{SubjectToken: tok.AccessToken})
	wantErr(t, err, service.ErrInvalidGrant, "exchange of a revoked grant's token")
}

func TestDisablePrincipal(t *testing.T) {
	h := newHarness(t)
	p := h.enroll("agent:gone", service.KindAgent)
	tok := h.refresh(p, "warden")
	if err := h.svc.DisablePrincipal(h.ctx, as("agent:x", service.KindAgent), "agent:gone", ""); err == nil {
		t.Fatal("a non-owner disabled a principal")
	}
	if err := h.svc.DisablePrincipal(h.ctx, h.owner, "agent:gone", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.VerifyOwn(tok.AccessToken, ""); err == nil {
		t.Fatal("a disabled principal's token verifies")
	}
	_, err := h.svc.Refresh(h.ctx, tok.RefreshToken, service.MintRequest{Audience: "warden"})
	wantErr(t, err, service.ErrInvalidGrant, "disabled principal refresh")
}

func TestActorChain(t *testing.T) {
	h := newHarness(t)
	agentParent := h.enroll("agent:lead", service.KindAgent)
	agentTok := h.refresh(agentParent, "warden")
	// The agent enrolls its own session: ground tier, ready at once, and the session's tokens carry act.
	agent := as("agent:lead", service.KindAgent)
	e, err := h.svc.Enroll(h.ctx, &agent, service.EnrollInput{Sub: "session:lead-1", Kind: service.KindSession, Parent: "agent:lead"})
	if err != nil || e.Status != "ready" {
		t.Fatalf("session enrollment: %+v %v", e, err)
	}
	_, got, err := h.svc.PollEnrollment(h.ctx, e.ID, e.PollToken)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	st := h.refresh(got.RefreshToken, "warden")
	c, err := h.svc.VerifyOwn(st.AccessToken, "warden")
	if err != nil || c.Act == nil || c.Act.Sub != "agent:lead" || c.Kind != service.KindSession || st.TTL != 900 {
		t.Fatalf("session token claims %+v ttl %d err %v", c, st.TTL, err)
	}
	// An actor token adds the actor as the outer link.
	ex, err := h.svc.Exchange(h.ctx, service.ExchangeRequest{SubjectToken: st.AccessToken, ActorToken: agentTok.AccessToken})
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := h.svc.VerifyOwn(ex.AccessToken, "")
	if c2.Act == nil || c2.Act.Sub != "agent:lead" {
		t.Fatalf("exchanged act %+v", c2.Act)
	}
	// Someone else's agent cannot enroll a session under agent:lead at ground tier.
	other := as("agent:other", service.KindAgent)
	e2, err := h.svc.Enroll(h.ctx, &other, service.EnrollInput{Sub: "session:lead-2", Kind: service.KindSession, Parent: "agent:lead"})
	if err != nil || e2.Status != "pending" || e2.Tier == "ground" {
		t.Fatalf("foreign session enrollment: %+v %v", e2, err)
	}
}
