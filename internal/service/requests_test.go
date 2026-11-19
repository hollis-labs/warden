package service_test

import (
	"testing"
	"time"

	"github.com/hollis-labs/warden/internal/approval"
	"github.com/hollis-labs/warden/internal/service"
)

func TestTiers(t *testing.T) {
	h := newHarness(t)
	h.enroll("agent:t", service.KindAgent)
	h.enroll("agent:u", service.KindAgent)
	me := as("agent:t", service.KindAgent)
	cases := []struct {
		name      string
		c         service.Caller
		in        service.RequestInput
		tier, rul string
		status    string
	}{
		{"llm use is ground", me, service.RequestInput{Audience: "llm-gateway", Scopes: []string{"llm-gateway.chat"}}, "ground", "llm-gateway-use", "approved"},
		{"read scopes are ground", me, service.RequestInput{Audience: "tesseract", Scopes: []string{"tesseract.read"}}, "ground", "read-scopes", "approved"},
		{"write scopes default to critical", me, service.RequestInput{Audience: "tesseract", Scopes: []string{"tesseract.write"}}, "critical", "default", "pending"},
		{"admin is critical", me, service.RequestInput{Audience: "torque", Scopes: []string{"torque.admin"}}, "critical", "floor:admin-scope", "pending"},
		{"authority over warden is critical", me, service.RequestInput{Audience: "warden", Scopes: []string{"warden.admin"}}, "critical", "floor:admin-scope", "pending"},
		{"for another principal is critical", me, service.RequestInput{Principal: "agent:u", Audience: "llm-gateway", Scopes: []string{"llm-gateway.chat"}}, "critical", "floor:other-principal", "pending"},
		{"owner-direct is approved", h.owner, service.RequestInput{Principal: "agent:u", Audience: "tesseract", Scopes: []string{"tesseract.write"}}, "critical", "floor:owner-direct", "approved"},
	}
	for _, tc := range cases {
		r, err := h.svc.CreateRequest(h.ctx, tc.c, tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if r.Tier != tc.tier || r.Rule != tc.rul || r.Status != tc.status {
			t.Errorf("%s: tier %s rule %s status %s, want %s %s %s", tc.name, r.Tier, r.Rule, r.Status, tc.tier, tc.rul, tc.status)
		}
		if tc.status == "pending" && r.ApprovalID == "" {
			t.Errorf("%s: pending request was not submitted to Gatecrasher", tc.name)
		}
	}
	// A renewal inside an existing grant is ground, even where the original needed approval.
	r, _ := h.svc.CreateRequest(h.ctx, as("agent:u", service.KindAgent), service.RequestInput{Audience: "tesseract", Scopes: []string{"tesseract.write"}})
	if r.Tier != "ground" || r.Rule != "floor:renewal" {
		t.Fatalf("renewal: tier %s rule %s", r.Tier, r.Rule)
	}
	// An unknown principal cannot file.
	_, err := h.svc.CreateRequest(h.ctx, as("agent:nobody", service.KindAgent), service.RequestInput{Audience: "llm-gateway", Scopes: []string{"llm-gateway.chat"}})
	wantErr(t, err, service.ErrNotFound, "unenrolled principal")
}

func pendingCritical(t *testing.T, h *harness) service.Request {
	t.Helper()
	h.enroll("agent:p", service.KindAgent)
	r, err := h.svc.CreateRequest(h.ctx, as("agent:p", service.KindAgent), service.RequestInput{Audience: "tesseract", Scopes: []string{"tesseract.write"}, Purpose: "index docs"})
	if err != nil || r.Status != "pending" || r.Tier != "critical" {
		t.Fatalf("setup: %+v %v", r, err)
	}
	return r
}

func TestGatecrasherApproval(t *testing.T) {
	h := newHarness(t)
	r := pendingCritical(t, h)
	// Still pending: no grant, so no token.
	if err := h.svc.Sync(h.ctx, r.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.fake.Decide(r.ApprovalID, approval.Approved, approval.Party{Sub: "user:1", Kind: "human"}, nil); err != nil {
		t.Fatal(err)
	}
	got, err := h.svc.GetRequest(h.ctx, as("agent:p", service.KindAgent), r.ID)
	if err != nil || got.Status != "approved" || got.GrantID == "" || got.DecidedBy != "user:1" {
		t.Fatalf("after approval: %+v %v", got, err)
	}
	g, err := h.svc.GetGrant(h.ctx, h.owner, got.GrantID)
	if err != nil || g.ApprovalRef != r.ApprovalID || g.Approver != "user:1" || g.Tier != "critical" {
		t.Fatalf("grant record %+v %v", g, err)
	}
}

func TestCriticalNeedsTheOwner(t *testing.T) {
	h := newHarness(t)
	r := pendingCritical(t, h)
	// An agent approving a critical request: Warden refuses the decision and the request stays pending.
	if err := h.fake.Decide(r.ApprovalID, approval.Approved, approval.Party{Sub: "agent:chief", Kind: "agent"}, nil); err != nil {
		t.Fatal(err)
	}
	_ = h.svc.Sync(h.ctx, r.ID, 0)
	got, _ := h.svc.GetRequest(h.ctx, h.owner, r.ID)
	if got.Status != "pending" || got.GrantID != "" {
		t.Fatalf("critical approved by an agent: %+v", got)
	}
}

func TestNoSelfApproval(t *testing.T) {
	h := newHarness(t)
	r := pendingCritical(t, h)
	_ = h.fake.Decide(r.ApprovalID, approval.Approved, approval.Party{Sub: "agent:p", Kind: "human"}, nil)
	_ = h.svc.Sync(h.ctx, r.ID, 0)
	if got, _ := h.svc.GetRequest(h.ctx, h.owner, r.ID); got.Status != "pending" {
		t.Fatalf("self-approval accepted: %+v", got)
	}
}

// A decision signed for a different request (or by an unknown key) is refused.
func TestDecisionBinding(t *testing.T) {
	h := newHarness(t)
	r := pendingCritical(t, h)
	v := approval.Verifier{Keys: h.fake.Keys(), Now: h.clock.Now}
	now := h.clock.Now()
	base := approval.Decision{Iss: "gatecrasher", Aud: "warden", ApprovalID: r.ApprovalID, RequestID: r.ID, Outcome: approval.Approved,
		Tier: "critical", Decider: approval.Party{Sub: "user:1", Kind: "human"}, DecidedAt: now, Exp: now.Add(5 * time.Minute).Unix()}
	p := approval.PrincipalRef{Sub: r.Principal, Kind: r.PrincipalKind}
	req := approval.Requested{Action: r.Action, Audience: r.Audience, Scopes: r.Scopes, TTLSeconds: r.TTLSeconds}
	want := approval.Expect{ApprovalID: r.ApprovalID, RequestID: r.ID, Digest: approval.Digest(p, req, r.Tier), Tier: r.Tier, Requested: req}
	good := base
	good.RequestDigest = want.Digest
	jws, _ := h.fake.SignRaw(good)
	if _, err := v.Verify(h.ctx, jws, want); err != nil {
		t.Fatalf("a good decision fails: %v", err)
	}
	mutate := map[string]func(d *approval.Decision){
		"other request":     func(d *approval.Decision) { d.RequestID = "req_other" },
		"widened digest":    func(d *approval.Decision) { d.RequestDigest = "sha256:00" },
		"other audience":    func(d *approval.Decision) { d.Aud = "tachyon" },
		"other issuer":      func(d *approval.Decision) { d.Iss = "mallory" },
		"expired":           func(d *approval.Decision) { d.Exp = now.Add(-time.Second).Unix() },
		"downgraded tier":   func(d *approval.Decision) { d.Tier = "elevated" },
		"widening narrowed": func(d *approval.Decision) { d.Narrowed = &approval.Narrowed{Scopes: []string{"tesseract.admin"}} },
	}
	for name, m := range mutate {
		d := good
		m(&d)
		jws, _ := h.fake.SignRaw(d)
		if _, err := v.Verify(h.ctx, jws, want); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	other := approval.NewFake()
	forged, _ := other.SignRaw(good)
	if _, err := v.Verify(h.ctx, forged, want); err == nil {
		t.Error("a decision signed by an unknown key was accepted")
	}
}

func TestDeniedAndWithdrawn(t *testing.T) {
	h := newHarness(t)
	r := pendingCritical(t, h)
	_ = h.fake.Decide(r.ApprovalID, approval.Denied, approval.Party{Sub: "user:1", Kind: "human"}, nil)
	got, _ := h.svc.GetRequest(h.ctx, h.owner, r.ID)
	if got.Status != "denied" || got.GrantID != "" {
		t.Fatalf("denied: %+v", got)
	}
	r2, _ := h.svc.CreateRequest(h.ctx, as("agent:p", service.KindAgent), service.RequestInput{Audience: "torque", Scopes: []string{"torque.write"}})
	if _, err := h.svc.Withdraw(h.ctx, as("agent:zz", service.KindAgent), r2.ID); err == nil {
		t.Fatal("a stranger withdrew my request")
	}
	w, err := h.svc.Withdraw(h.ctx, as("agent:p", service.KindAgent), r2.ID)
	if err != nil || w.Status != "withdrawn" {
		t.Fatalf("withdraw: %+v %v", w, err)
	}
}

func TestRequestExpires(t *testing.T) {
	h := newHarness(t)
	r := pendingCritical(t, h)
	h.clock.Add(8 * 24 * time.Hour)
	if err := h.svc.Sync(h.ctx, r.ID, 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.svc.GetRequest(h.ctx, h.owner, r.ID); got.Status != "expired" {
		t.Fatalf("status %s, want expired", got.Status)
	}
}

func TestOpenEnrollment(t *testing.T) {
	h := newHarness(t)
	e, err := h.svc.Enroll(h.ctx, nil, service.EnrollInput{Sub: "app:basalisk", Kind: service.KindApp, Display: "Basalisk",
		Audience: "llm-gateway", Scopes: []string{"llm-gateway.chat"}, Purpose: "companion app"})
	if err != nil || e.Status != "pending" || e.Tier != "elevated" || e.PollToken == "" {
		t.Fatalf("enroll: %+v %v", e, err)
	}
	// Wrong poll token: indistinguishable from a missing enrollment.
	if _, _, xerr := h.svc.PollEnrollment(h.ctx, e.ID, "wdn_e_wrong"); xerr == nil {
		t.Fatal("a wrong poll token was accepted")
	}
	st, got, err := h.svc.PollEnrollment(h.ctx, e.ID, e.PollToken)
	if err != nil || got != nil || st.Status != "pending" {
		t.Fatalf("pending poll: %+v %+v %v", st, got, err)
	}
	id, ok := h.fake.ApprovalFor(e.RequestID)
	if !ok {
		t.Fatal("enrollment was not sent to Gatecrasher")
	}
	pend := h.fake.Pending()
	if len(pend) != 1 || pend[0].ApproverClass != "approve.enroll" || pend[0].Tier != "elevated" {
		t.Fatalf("submitted %+v", pend)
	}
	if err = h.fake.Decide(id, approval.Approved, approval.Party{Sub: "agent:security-manager", Kind: "agent"}, nil); err != nil {
		t.Fatal(err)
	}
	_, got, err = h.svc.PollEnrollment(h.ctx, e.ID, e.PollToken)
	if err != nil || got == nil || got.Sub != "app:basalisk" {
		t.Fatalf("collect: %+v %v", got, err)
	}
	// Exactly once.
	if _, _, err := h.svc.PollEnrollment(h.ctx, e.ID, e.PollToken); err == nil {
		t.Fatal("the parent credential was delivered twice")
	}
	// The requested grant came with it.
	tok := h.refresh(got.RefreshToken, "llm-gateway")
	if tok.Scope != "llm-gateway.chat" {
		t.Fatalf("scope %q", tok.Scope)
	}
	// Enrolling an existing principal again is critical.
	e2, _ := h.svc.Enroll(h.ctx, nil, service.EnrollInput{Sub: "app:basalisk", Kind: service.KindApp})
	if e2.Tier != "critical" {
		t.Fatalf("re-enrollment tier %s", e2.Tier)
	}
}

func TestDeviceFlow(t *testing.T) {
	h := newHarness(t)
	d, err := h.svc.DeviceAuthorize(h.ctx, service.DeviceInput{Sub: "app:phone", Display: "Phone"})
	if err != nil || len(d.UserCode) != 9 || d.Interval != 5 || d.VerificationURIComplete == "" {
		t.Fatalf("authorize: %+v %v", d, err)
	}
	_, err = h.svc.DeviceToken(h.ctx, d.DeviceCode)
	wantErr(t, err, service.ErrAuthorizationPending, "first poll")
	_, err = h.svc.DeviceToken(h.ctx, d.DeviceCode)
	wantErr(t, err, service.ErrSlowDown, "fast poll")
	// Only the owner approves.
	if _, err = h.svc.ApproveDevice(h.ctx, as("agent:x", service.KindAgent), d.UserCode, true); err == nil {
		t.Fatal("an agent approved a device sign-in")
	}
	if _, err = h.svc.ApproveDevice(h.ctx, h.owner, d.UserCode, true); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(6 * time.Second)
	tok, err := h.svc.DeviceToken(h.ctx, d.DeviceCode)
	if err != nil || tok.Audience != "warden" || tok.RefreshToken == "" || tok.Sub != "app:phone" {
		t.Fatalf("token: %+v %v", tok, err)
	}
	_, err = h.svc.DeviceToken(h.ctx, d.DeviceCode)
	wantErr(t, err, service.ErrInvalidGrant, "second redemption")

	// Denied and expired codes.
	d2, _ := h.svc.DeviceAuthorize(h.ctx, service.DeviceInput{Sub: "app:tv"})
	_, _ = h.svc.ApproveDevice(h.ctx, h.owner, d2.UserCode, false)
	_, err = h.svc.DeviceToken(h.ctx, d2.DeviceCode)
	wantErr(t, err, service.ErrAccessDenied, "denied code")
	d3, _ := h.svc.DeviceAuthorize(h.ctx, service.DeviceInput{Sub: "app:watch"})
	h.clock.Add(16 * time.Minute)
	_, err = h.svc.DeviceToken(h.ctx, d3.DeviceCode)
	wantErr(t, err, service.ErrExpiredToken, "expired code")
}
