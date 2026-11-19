package service_test

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hollis-labs/libs/core/store/migrate"
	"github.com/hollis-labs/libs/core/store/storetest"

	"github.com/hollis-labs/warden/internal/approval"
	"github.com/hollis-labs/warden/internal/issuer"
	"github.com/hollis-labs/warden/internal/policy"
	"github.com/hollis-labs/warden/internal/service"
	"github.com/hollis-labs/warden/internal/storage"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type harness struct {
	t     *testing.T
	ctx   context.Context
	svc   *service.Service
	fake  *approval.Fake
	clock *clock
	owner service.Caller
}

const iss = "https://warden.test"

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	st := storetest.SQLite(t)
	fsys, root := storage.Migrations()
	if err := migrate.UpStore(ctx, st, migrate.Source{FS: fsys, Root: root}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	keys, err := issuer.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	fake := approval.NewFake()
	fake.Now = clk.Now
	svc, err := service.New(ctx, service.Options{Store: st, Keys: keys, Rules: rules, Approver: fake, DecisionKeys: fake.Keys(),
		Config: service.Config{Issuer: iss, VerificationURI: "https://warden.test/v1/device"}, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, ctx: ctx, svc: svc, fake: fake, clock: clk,
		owner: service.Caller{Sub: "user:1", Kind: service.KindHuman, Scopes: []string{"*"}, Admin: true, Human: true}}
}

// enroll makes sub a principal through the owner (owner-direct) and returns its first parent credential.
func (h *harness) enroll(sub, kind string) string {
	h.t.Helper()
	e, err := h.svc.Enroll(h.ctx, &h.owner, service.EnrollInput{Sub: sub, Kind: kind})
	if err != nil {
		h.t.Fatalf("enroll %s: %v", sub, err)
	}
	if e.Status != "ready" {
		h.t.Fatalf("owner enrollment of %s is %s, want ready", sub, e.Status)
	}
	_, got, err := h.svc.PollEnrollment(h.ctx, e.ID, e.PollToken)
	if err != nil || got == nil {
		h.t.Fatalf("collect %s: %v", sub, err)
	}
	return got.RefreshToken
}

// wardenToken refreshes parent into an aud=warden token, returning the token and the rotated parent.
func (h *harness) refresh(parent, aud string, sc ...string) service.Token {
	h.t.Helper()
	tok, err := h.svc.Refresh(h.ctx, parent, service.MintRequest{Audience: aud, Scopes: sc})
	if err != nil {
		h.t.Fatalf("refresh %s: %v", aud, err)
	}
	return tok
}

// as is the caller a Warden token for sub would produce.
func as(sub, kind string) service.Caller {
	return service.Caller{Sub: sub, Kind: kind, Scopes: []string{"warden.read", "warden.request", "warden.mcp"}}
}

// grant files a request as the principal itself and fails unless it is approved at once (ground).
func (h *harness) grant(sub, kind, aud string, sc ...string) service.Request {
	h.t.Helper()
	r, err := h.svc.CreateRequest(h.ctx, as(sub, kind), service.RequestInput{Audience: aud, Scopes: sc})
	if err != nil {
		h.t.Fatalf("request %s %v: %v", aud, sc, err)
	}
	if r.Status != "approved" || r.GrantID == "" {
		h.t.Fatalf("request %s %v: %s (tier %s rule %s), want approved", aud, sc, r.Status, r.Tier, r.Rule)
	}
	return r
}

func wantErr(t *testing.T, err, target error, what string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want %v", what, err, target)
	}
}

func base64URL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
