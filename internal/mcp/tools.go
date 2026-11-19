// Package wardenmcp registers Warden's MCP tools: file a credential request, check it, and list grants.
// Every tool runs as the verified caller (the guard's principal on /mcp, or the stdio token) and calls
// the service layer only.
package wardenmcp

import (
	"context"
	"errors"
	"fmt"

	gmcp "github.com/hollis-labs/libs/mcp/plugin-mcp/go-mcp/server"
	libauth "github.com/hollis-labs/libs/security/auth"

	"github.com/hollis-labs/warden/internal/scopes"
	"github.com/hollis-labs/warden/internal/service"
)

// Tools maps each tool name to the scope it needs.
var Tools = map[string]string{
	"warden_request":        "warden.request",
	"warden_request_status": "warden.read",
	"warden_grants_list":    "warden.read",
}

// RegisterScopes maps every tool to its scope.
func RegisterScopes(t *libauth.ScopeTable) {
	for name, scope := range Tools {
		t.Tool(name, scope)
	}
}

// Authorizer checks the caller may run a tool (Substrate's mcp.Authorize).
type Authorizer func(ctx context.Context, tool string) error

func callerOf(ctx context.Context) (service.Caller, error) {
	p, ok := libauth.FromContext(ctx)
	if !ok {
		return service.Caller{}, errors.New("unauthenticated")
	}
	c, ok := service.CallerFrom(p)
	if !ok {
		return service.Caller{}, errors.New("unauthenticated")
	}
	return c, nil
}

func str(args map[string]any, k string) string {
	s, _ := args[k].(string)
	return s
}

// Register adds the tools to srv.
func Register(srv *gmcp.Server, svc *service.Service, authorize Authorizer) {
	run := func(name string, f func(ctx context.Context, c service.Caller, args map[string]any) (any, error)) gmcp.ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			if err := authorize(ctx, name); err != nil {
				return nil, err
			}
			c, err := callerOf(ctx)
			if err != nil {
				return nil, err
			}
			return f(ctx, c, args)
		}
	}
	srv.RegisterChecked(gmcp.Tool{
		Name:  "warden_request",
		Title: "Request a credential grant",
		Description: "Ask Warden for a grant: an audience (one app id, e.g. llm-gateway) and scopes on it (e.g. llm-gateway.decide). " +
			"Policy sorts it: ground is granted at once; elevated and critical go to an approver through Gatecrasher. " +
			"Once granted, your existing Warden parent credential mints tokens for that audience; no secret is returned here.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"audience":    map[string]any{"type": "string", "description": "one app id, e.g. llm-gateway"},
				"scopes":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "<audience>.<verb> scopes"},
				"ttl_seconds": map[string]any{"type": "integer", "description": "grant lifetime; default 30 days"},
				"purpose":     map[string]any{"type": "string", "description": "why you need it (shown to the approver)"},
				"task_id":     map[string]any{"type": "string", "description": "the task this is for (evidence)"},
				"principal":   map[string]any{"type": "string", "description": "only for your own session; default yourself"},
			},
			"required": []string{"audience", "scopes"},
		},
		Handler: run("warden_request", func(ctx context.Context, c service.Caller, args map[string]any) (any, error) {
			var sc []string
			switch v := args["scopes"].(type) {
			case []any:
				for _, x := range v {
					if s, ok := x.(string); ok {
						sc = append(sc, s)
					}
				}
			case string:
				sc = scopes.Split(v)
			}
			ttl, _ := args["ttl_seconds"].(float64)
			in := service.RequestInput{Principal: str(args, "principal"), Audience: str(args, "audience"), Scopes: sc,
				TTLSeconds: int64(ttl), Purpose: str(args, "purpose"), Evidence: map[string]string{}}
			if t := str(args, "task_id"); t != "" {
				in.Evidence["task_id"] = t
			}
			return svc.CreateRequest(ctx, c, in)
		}),
	}, gmcp.Writes())
	srv.RegisterChecked(gmcp.Tool{
		Name:        "warden_request_status",
		Title:       "Check a credential request",
		Description: "Return a Warden request by id: its tier, status (pending, approved, denied, expired, withdrawn) and grant id once approved.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"id": map[string]any{"type": "string", "description": "request id (req_...)"}},
			"required":   []string{"id"},
		},
		Handler: run("warden_request_status", func(ctx context.Context, c service.Caller, args map[string]any) (any, error) {
			id := str(args, "id")
			if id == "" {
				return nil, fmt.Errorf("id is required")
			}
			return svc.GetRequest(ctx, c, id)
		}),
	}, gmcp.Reads("reads the caller's own request status"))
	srv.RegisterChecked(gmcp.Tool{
		Name:        "warden_grants_list",
		Title:       "List my grants",
		Description: "List the grants you hold (audience, scopes, tier, expiry, revocation). The owner may name another principal.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"principal": map[string]any{"type": "string", "description": "default yourself"}},
		},
		Handler: run("warden_grants_list", func(ctx context.Context, c service.Caller, args map[string]any) (any, error) {
			gs, err := svc.ListGrants(ctx, c, str(args, "principal"))
			return map[string]any{"grants": gs}, err
		}),
	}, gmcp.Reads("lists the caller's own grants"))
}
