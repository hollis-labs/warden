package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/hollis-labs/libs/security/secrets/tokenfile"
	"github.com/hollis-labs/substrate/module"
	"github.com/hollis-labs/substrate/modules/auth"
	"github.com/hollis-labs/substrate/modules/database"
	"github.com/hollis-labs/substrate/modules/httphost"
	"github.com/hollis-labs/substrate/modules/identity"
	"github.com/hollis-labs/substrate/modules/mcp"

	"github.com/hollis-labs/warden/internal/api"
	"github.com/hollis-labs/warden/internal/approval"
	"github.com/hollis-labs/warden/internal/hostguard"
	wardenmcp "github.com/hollis-labs/warden/internal/mcp"
	"github.com/hollis-labs/warden/internal/policy"
	"github.com/hollis-labs/warden/internal/service"
	"github.com/hollis-labs/warden/internal/settings"
)

func serveCmd(ctx context.Context, app *module.App) *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use: "serve", Short: "Serve the issuer, the token endpoint, the request API and MCP", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if addr != "" {
				cfg, _ := app.Config["httphost"].(map[string]any)
				if cfg == nil {
					cfg = map[string]any{}
					app.Config["httphost"] = cfg
				}
				cfg["addr"] = addr
			}
			return serve(ctx, app, nil)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "", "Listener address (overrides httphost.addr)")
	cmd.Flags().Bool("managed", false, "Supervised run; class 1 auth is always enforced")
	return cmd
}

// fakeAdapter exposes the in-process fake Gatecrasher to the owner-only dev routes.
type fakeAdapter struct{ f *approval.Fake }

func (a fakeAdapter) PendingJSON() any {
	out := []map[string]any{}
	for _, r := range a.f.Pending() {
		id, _ := a.f.ApprovalFor(r.IdempotencyKey)
		out = append(out, map[string]any{"approval_id": id, "request_id": r.IdempotencyKey, "tier": r.Tier,
			"principal": r.Principal, "requested": r.Requested, "purpose": r.Purpose, "approver_class": r.ApproverClass})
	}
	return out
}

func (a fakeAdapter) Decide(id, outcome, decider string) error {
	return a.f.Decide(id, approval.Status(outcome), approval.Party{Sub: decider, Kind: "human"}, nil)
}

// approvals builds the Gatecrasher client from settings.
func approvals(cfg settings.Approvals) (approval.Approver, approval.KeySet, *approval.Fake, error) {
	switch cfg.Mode {
	case settings.ApprovalsFake:
		f := approval.NewFake()
		f.Issuer = cfg.Issuer
		return f, f.Keys(), f, nil
	case settings.ApprovalsGatecrasher:
		var keys approval.KeySet
		if cfg.JWKSFile != "" {
			k, err := approval.LoadJWKSFile(cfg.JWKSFile)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("approvals.jwks_file: %w", err)
			}
			keys = k
		} else {
			keys = &approval.RemoteKeys{URL: cfg.JWKSURL}
		}
		c := &approval.HTTPClient{BaseURL: cfg.URL}
		if cfg.TokenFile != "" {
			path := cfg.TokenFile
			c.Token = func(context.Context) (string, error) { return tokenfile.Read(path) }
		}
		return c, keys, nil, nil
	default:
		return nil, nil, nil, nil
	}
}

// serve runs the HTTP host until ctx ends. ready, when set, learns the bound address.
func serve(ctx context.Context, app *module.App, ready func(net.Addr)) error {
	if guard := auth.Guard(app); guard == nil || string(guard.Mode()) != "enforce" {
		return errors.New("class 1 applications require enforced auth")
	}
	id := identity.From(app)
	if id == nil {
		return errors.New("the identity module must be started")
	}
	st := database.From(app)
	if st == nil {
		return errors.New("the database module must be started")
	}
	if issuerKeys == nil {
		return errors.New("the issuer keys are not open")
	}
	cfg, err := settings.Parse(app.Config[settings.Key])
	if err != nil {
		return err
	}
	rules, err := policy.Load(cfg.PolicyFile)
	if err != nil {
		return err
	}
	approver, decisionKeys, fake, err := approvals(cfg.Approvals)
	if err != nil {
		return err
	}
	if fake != nil {
		slog.Warn("warden: approvals.mode is fake: elevated and critical requests are decided through the owner-only dev routes, not Gatecrasher")
	}
	svc, err := service.New(ctx, service.Options{Store: st, Keys: issuerKeys, Rules: rules, Approver: approver, DecisionKeys: decisionKeys,
		Deny: denyList, Config: service.Config{Issuer: cfg.Issuer, VerificationURI: cfg.VerificationURI, GatecrasherIssuer: cfg.Approvals.Issuer}})
	if err != nil {
		return err
	}
	table := auth.ScopeTable(app)
	api.RegisterScopes(table, fake != nil)
	wardenmcp.RegisterScopes(table)
	if srv := mcp.Server(app); srv != nil {
		wardenmcp.Register(srv, svc, func(ctx context.Context, tool string) error { return mcp.Authorize(ctx, app, tool) })
	}
	var fa api.Fake
	if fake != nil {
		fa = fakeAdapter{fake}
	}
	h := api.New(svc, api.Metadata{Issuer: cfg.Issuer, BaseURL: cfg.PublicURL}, fa)
	handler, err := httphost.Handler(app, httphost.Options{Routes: h.Mux(), Mounts: h.Mounts(), NotFound: httphost.NotFoundFlat})
	if err != nil {
		return err
	}
	// Outermost first: the Host check (DNS rebinding) and forwarding-header hygiene, then the session cookie
	// becomes the bearer the guard verifies, then the host (guard, routes).
	handler = hostguard.Handler(cfg.AllowedHosts, id.Middleware(handler))

	bg, stop := context.WithCancel(ctx)
	defer stop()
	go svc.RunWorker(bg, 5*time.Second)
	go issuerKeys.Maintain(bg, 0, func() {
		if err := auth.RefreshKeys(bg, app); err != nil {
			slog.Warn("warden: verifier key refresh failed", "err", err)
		}
	})
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-bg.Done():
				return
			case <-t.C:
				if err := svc.PruneMinted(bg); err != nil {
					slog.Warn("warden: prune failed", "err", err)
				}
			}
		}
	}()
	return httphost.Serve(ctx, app, handler, httphost.ServeOptions{
		Ready: func(addr net.Addr) {
			slog.Info("warden listening", "addr", addr.String(), "issuer", cfg.Issuer, "approvals", cfg.Approvals.Mode)
			if ready != nil {
				ready(addr)
			}
		},
	})
}
