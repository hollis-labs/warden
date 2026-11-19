// Package api is Warden's HTTP API. Two halves:
//
//   - Protocol endpoints, open (no guard) because they authenticate themselves or are public discovery:
//     /.well-known/jwks.json, /.well-known/oauth-authorization-server, /v1/denylist, /v1/token,
//     /v1/enroll, /v1/enroll/{id}/poll, /v1/device/code, /v1/device.
//   - The management API under /api/v1/, behind the Substrate guard, one scope per route (Routes()).
//
// Handlers decode, call the service layer and encode. They hold no SQL (docs/transport-boundary.md).
package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	libauth "github.com/hollis-labs/libs/security/auth"
	"github.com/hollis-labs/substrate/apierr"

	"github.com/hollis-labs/warden/internal/service"
)

// Scopes on Warden's own audience.
const (
	ScopeRead    = "warden.read"
	ScopeRequest = "warden.request"
	ScopeAdmin   = "warden.admin"
)

// Route is one guarded API route and the scope it needs. Every guarded route is listed here, so the scope
// table and the mux cannot disagree (TestEveryRouteHasAScope).
type Route struct{ Method, Pattern, Scope string }

// Routes lists every guarded route with its scope. Specific patterns come first (first match wins).
func Routes(dev bool) []Route {
	r := []Route{
		{http.MethodGet, "/api/v1/whoami", ScopeRead},
		{http.MethodPost, "/api/v1/requests", ScopeRequest},
		{http.MethodGet, "/api/v1/requests", ScopeRead},
		{http.MethodGet, "/api/v1/requests/{id}", ScopeRead},
		{http.MethodPost, "/api/v1/requests/{id}/withdraw", ScopeRequest},
		{http.MethodGet, "/api/v1/grants", ScopeRead},
		{http.MethodGet, "/api/v1/grants/{id}", ScopeRead},
		{http.MethodPost, "/api/v1/grants/{id}/revoke", ScopeRequest},
		{http.MethodGet, "/api/v1/families", ScopeRead},
		{http.MethodPost, "/api/v1/families/{id}/revoke", ScopeRequest},
		{http.MethodPost, "/api/v1/enroll", ScopeRequest},
		{http.MethodPost, "/api/v1/device/approve", ScopeAdmin},
		{http.MethodPost, "/api/v1/principals/disable", ScopeAdmin},
		{http.MethodGet, "/api/v1/audit", ScopeAdmin},
		{http.MethodPost, "/api/v1/keys/rotate", ScopeAdmin},
	}
	if dev {
		r = append(r,
			Route{http.MethodGet, "/api/v1/dev/approvals", ScopeAdmin},
			Route{http.MethodPost, "/api/v1/dev/approvals/{id}/decide", ScopeAdmin})
	}
	return r
}

// RegisterScopes declares the scope of every guarded route on the guard's table.
func RegisterScopes(t *libauth.ScopeTable, dev bool) {
	for _, rt := range Routes(dev) {
		t.Route(rt.Method, rt.Pattern, rt.Scope)
	}
}

// Fake is the dev approval hook (approvals.mode: fake); nil otherwise.
type Fake interface {
	PendingJSON() any
	Decide(id, outcome, decider string) error
}

// Handler serves Warden's routes over the service layer.
type Handler struct {
	svc  *service.Service
	meta Metadata
	fake Fake
}

// New builds the handler.
func New(svc *service.Service, meta Metadata, fake Fake) *Handler {
	return &Handler{svc: svc, meta: meta, fake: fake}
}

// Mux returns the guarded routes for httphost.Options.Routes.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/whoami", h.whoami)
	mux.HandleFunc("POST /api/v1/requests", h.createRequest)
	mux.HandleFunc("GET /api/v1/requests", h.listRequests)
	mux.HandleFunc("GET /api/v1/requests/{id}", h.getRequest)
	mux.HandleFunc("POST /api/v1/requests/{id}/withdraw", h.withdraw)
	mux.HandleFunc("GET /api/v1/grants", h.listGrants)
	mux.HandleFunc("GET /api/v1/grants/{id}", h.getGrant)
	mux.HandleFunc("POST /api/v1/grants/{id}/revoke", h.revokeGrant)
	mux.HandleFunc("GET /api/v1/families", h.listFamilies)
	mux.HandleFunc("POST /api/v1/families/{id}/revoke", h.revokeFamily)
	mux.HandleFunc("POST /api/v1/enroll", h.enrollAuthed)
	mux.HandleFunc("POST /api/v1/device/approve", h.approveDevice)
	mux.HandleFunc("POST /api/v1/principals/disable", h.disable)
	mux.HandleFunc("GET /api/v1/audit", h.audit)
	mux.HandleFunc("POST /api/v1/keys/rotate", h.rotate)
	if h.fake != nil {
		mux.HandleFunc("GET /api/v1/dev/approvals", h.devList)
		mux.HandleFunc("POST /api/v1/dev/approvals/{id}/decide", h.devDecide)
	}
	return mux
}

func caller(w http.ResponseWriter, r *http.Request) (service.Caller, bool) {
	p, ok := libauth.FromContext(r.Context())
	if !ok {
		apierr.Write(w, http.StatusUnauthorized, "unauthorized", "Sign in required", nil)
		return service.Caller{}, false
	}
	c, ok := service.CallerFrom(p)
	if !ok {
		apierr.Write(w, http.StatusUnauthorized, "unauthorized", "Sign in required", nil)
	}
	return c, ok
}

// fail maps a service error to a status. Messages are the service's (they hold no secret).
func fail(w http.ResponseWriter, err error) {
	code, status := "internal", http.StatusInternalServerError
	switch {
	case errors.Is(err, service.ErrInvalid), errors.Is(err, service.ErrInvalidScope):
		code, status = "invalid_request", http.StatusBadRequest
	case errors.Is(err, service.ErrForbidden):
		code, status = "forbidden", http.StatusForbidden
	case errors.Is(err, service.ErrNotFound):
		code, status = "not_found", http.StatusNotFound
	case errors.Is(err, service.ErrConflict):
		code, status = "conflict", http.StatusConflict
	case errors.Is(err, service.ErrUnavailable):
		code, status = "unavailable", http.StatusServiceUnavailable
	}
	msg := "Internal error"
	if status != http.StatusInternalServerError {
		msg = service.Describe(err)
	} else {
		slog.Error("warden: request failed", "err", err)
	}
	apierr.Write(w, status, code, msg, nil)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apierr.Write(w, http.StatusBadRequest, "invalid_request", "invalid JSON body: "+err.Error(), nil)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) whoami(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h *Handler) createRequest(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	var in service.RequestInput
	if !decode(w, r, &in) {
		return
	}
	req, err := h.svc.CreateRequest(r.Context(), c, in)
	if err != nil {
		fail(w, err)
		return
	}
	status := http.StatusCreated
	if req.Status == "pending" {
		status = http.StatusAccepted
	}
	writeJSON(w, status, req)
}

func (h *Handler) listRequests(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	rs, err := h.svc.ListRequests(r.Context(), c, r.URL.Query().Get("all") == "true", r.URL.Query().Get("status"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": rs})
}

func (h *Handler) getRequest(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	req, err := h.svc.GetRequest(r.Context(), c, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (h *Handler) withdraw(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	req, err := h.svc.Withdraw(r.Context(), c, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (h *Handler) listGrants(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	gs, err := h.svc.ListGrants(r.Context(), c, r.URL.Query().Get("principal"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": gs})
}

func (h *Handler) getGrant(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	g, err := h.svc.GetGrant(r.Context(), c, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

type reasonBody struct {
	Reason string `json:"reason,omitempty"`
}

func (h *Handler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	var in reasonBody
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	g, err := h.svc.RevokeGrant(r.Context(), c, r.PathValue("id"), in.Reason)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (h *Handler) listFamilies(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	fs, err := h.svc.ListFamilies(r.Context(), c, r.URL.Query().Get("principal"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"families": fs})
}

func (h *Handler) revokeFamily(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	var in reasonBody
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	if err := h.svc.RevokeFamily(r.Context(), c, r.PathValue("id"), in.Reason); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": r.PathValue("id")})
}

func (h *Handler) enrollAuthed(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	h.enrollAs(w, r, &c)
}

func (h *Handler) approveDevice(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	var in struct {
		UserCode string `json:"user_code"`
		Deny     bool   `json:"deny,omitempty"`
	}
	if !decode(w, r, &in) {
		return
	}
	req, err := h.svc.ApproveDevice(r.Context(), c, in.UserCode, !in.Deny)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	var in struct {
		Sub    string `json:"sub"`
		Reason string `json:"reason,omitempty"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := h.svc.DisablePrincipal(r.Context(), c, in.Sub, in.Reason); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"disabled": in.Sub})
}

func (h *Handler) audit(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	es, err := h.svc.Audit(r.Context(), c, r.URL.Query().Get("subject"), 100)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": es})
}

func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	kids, err := h.svc.RotateKeys(r.Context(), c)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kids": kids})
}

func (h *Handler) devList(w http.ResponseWriter, r *http.Request) {
	if _, ok := caller(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": h.fake.PendingJSON()})
}

func (h *Handler) devDecide(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(w, r)
	if !ok {
		return
	}
	var in struct {
		Outcome string `json:"outcome"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := h.fake.Decide(r.PathValue("id"), in.Outcome, c.Sub); err != nil {
		apierr.Write(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"decided": r.PathValue("id"), "outcome": in.Outcome})
}

// bearer reads an Authorization: Bearer value.
func bearer(r *http.Request) (string, bool) {
	v := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(v, "Bearer ")
	return strings.TrimSpace(tok), ok && strings.TrimSpace(tok) != ""
}
