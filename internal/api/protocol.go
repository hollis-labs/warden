package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hollis-labs/substrate/apierr"
	"github.com/hollis-labs/substrate/modules/httphost"

	"github.com/hollis-labs/warden/internal/scopes"
	"github.com/hollis-labs/warden/internal/service"
)

// Grant types /v1/token accepts.
const (
	GrantRefresh  = "refresh_token"
	GrantExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantDevice   = "urn:ietf:params:oauth:grant-type:device_code"
	TokenTypeJWT  = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // G101: an RFC 8693 token type URN, not a credential
)

// Metadata is the RFC 8414 authorization-server metadata document's inputs.
type Metadata struct {
	Issuer  string // the iss of every token
	BaseURL string // public base URL of this Warden (no trailing slash)
}

// Mounts are the open protocol endpoints. They authenticate themselves (a parent credential, a poll token,
// a device code, a subject token) or are public discovery, so the guard does not wrap them; their responses
// keep the OAuth error shape (Raw).
func (h *Handler) Mounts() []httphost.Mount {
	open := func(p string, f http.HandlerFunc) httphost.Mount {
		return httphost.Mount{Pattern: p, Handler: f, Open: true, Raw: true}
	}
	return []httphost.Mount{
		open("GET /.well-known/jwks.json", h.jwks),
		open("GET /.well-known/oauth-authorization-server", h.metadata),
		open("GET /v1/denylist", h.denylist),
		open("POST /v1/token", h.token),
		open("POST /v1/enroll", h.enrollOpen),
		open("POST /v1/enroll/{id}/poll", h.pollEnroll),
		open("POST /v1/device/code", h.deviceCode),
		open("GET /v1/device", h.deviceInfo),
	}
}

func (h *Handler) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(h.svc.Keys().JWKS())
}

func (h *Handler) metadata(w http.ResponseWriter, _ *http.Request) {
	b := h.meta.BaseURL
	doc := map[string]any{
		"issuer":                                h.meta.Issuer,
		"jwks_uri":                              b + "/.well-known/jwks.json",
		"token_endpoint":                        b + "/v1/token",
		"device_authorization_endpoint":         b + "/v1/device/code",
		"grant_types_supported":                 []string{GrantRefresh, GrantExchange, GrantDevice},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"response_types_supported":              []string{},
		"scopes_supported":                      []string{"warden.read", "warden.request", "warden.mcp"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"EdDSA"},
		"id_token_signing_alg_values_supported":            []string{"EdDSA"},
		// Warden extensions.
		"denylist_uri":         b + "/v1/denylist",
		"enrollment_endpoint":  b + "/v1/enroll",
		"requests_endpoint":    b + "/api/v1/requests",
		"access_token_ttl":     map[string]int{"agent": 900, "session": 900, "human": 900, "app": 3600, "machine": 3600},
		"refresh_token_rotate": true,
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSONRaw(w, http.StatusOK, doc)
}

func (h *Handler) denylist(w http.ResponseWriter, r *http.Request) {
	body, etag := h.svc.DenyListDoc()
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func writeJSONRaw(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// oauthError writes the RFC 6749 §5.2 error shape.
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSONRaw(w, status, map[string]string{"error": code, "error_description": desc})
}

func oauthFail(w http.ResponseWriter, err error) {
	desc := service.Describe(err)
	switch {
	case errors.Is(err, service.ErrAuthorizationPending):
		oauthError(w, http.StatusBadRequest, "authorization_pending", "the owner has not decided yet")
	case errors.Is(err, service.ErrSlowDown):
		oauthError(w, http.StatusBadRequest, "slow_down", "poll less often")
	case errors.Is(err, service.ErrAccessDenied):
		oauthError(w, http.StatusBadRequest, "access_denied", "the sign-in was refused")
	case errors.Is(err, service.ErrExpiredToken):
		oauthError(w, http.StatusBadRequest, "expired_token", "the device code expired")
	case errors.Is(err, service.ErrInvalidGrant):
		oauthError(w, http.StatusBadRequest, "invalid_grant", desc)
	case errors.Is(err, service.ErrInvalidScope):
		oauthError(w, http.StatusBadRequest, "invalid_scope", desc)
	case errors.Is(err, service.ErrInvalid):
		oauthError(w, http.StatusBadRequest, "invalid_request", desc)
	case errors.Is(err, service.ErrUnavailable):
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", desc)
	default:
		oauthError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}

// tokenParams reads the token request as a form (RFC 6749) or as JSON.
func tokenParams(r *http.Request) (url.Values, error) {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	body := io.LimitReader(r.Body, 32<<10)
	if ct == "application/json" {
		var m map[string]any
		if err := json.NewDecoder(body).Decode(&m); err != nil {
			return nil, err
		}
		v := url.Values{}
		for k, x := range m {
			switch t := x.(type) {
			case string:
				v.Set(k, t)
			case float64:
				v.Set(k, strconv.FormatInt(int64(t), 10))
			case []any:
				var parts []string
				for _, p := range t {
					if s, ok := p.(string); ok {
						parts = append(parts, s)
					}
				}
				v.Set(k, strings.Join(parts, " "))
			}
		}
		return v, nil
	}
	b, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	return url.ParseQuery(string(b))
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	v, err := tokenParams(r)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unreadable token request")
		return
	}
	aud := v.Get("audience")
	if aud == "" && v.Get("resource") != "" {
		// RFC 8707: a resource indicator. Warden audiences are app ids; accept a bare id here too.
		aud = v.Get("resource")
		if u, xerr := url.Parse(aud); xerr == nil && u.Host != "" {
			aud = strings.SplitN(u.Hostname(), ".", 2)[0]
		}
	}
	var sc []string
	if s := v.Get("scope"); s != "" {
		sc = scopes.Split(s)
	}
	var ttl time.Duration
	if t := v.Get("ttl_seconds"); t != "" {
		n, xerr := strconv.Atoi(t)
		if xerr != nil || n <= 0 {
			oauthError(w, http.StatusBadRequest, "invalid_request", "ttl_seconds must be a positive integer")
			return
		}
		ttl = time.Duration(n) * time.Second
	}
	mr := service.MintRequest{Audience: aud, Scopes: sc, TTL: ttl}
	var tok service.Token
	switch v.Get("grant_type") {
	case GrantRefresh:
		parent := v.Get("refresh_token")
		if parent == "" {
			parent, _ = bearer(r)
		}
		tok, err = h.svc.Refresh(r.Context(), parent, mr)
	case GrantExchange:
		if st := v.Get("subject_token_type"); st != "" && st != TokenTypeJWT && st != "urn:ietf:params:oauth:token-type:jwt" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "subject_token_type must be an access token")
			return
		}
		tok, err = h.svc.Exchange(r.Context(), service.ExchangeRequest{SubjectToken: v.Get("subject_token"), ActorToken: v.Get("actor_token"), MintRequest: mr})
	case GrantDevice:
		tok, err = h.svc.DeviceToken(r.Context(), v.Get("device_code"))
	case "":
		oauthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
		return
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use refresh_token, token-exchange or device_code")
		return
	}
	if err != nil {
		oauthFail(w, err)
		return
	}
	writeJSONRaw(w, http.StatusOK, tok)
}

func (h *Handler) enrollOpen(w http.ResponseWriter, r *http.Request) {
	if _, ok := bearer(r); ok {
		// A credential on the open path is a client mistake: authenticated enrollment is /api/v1/enroll.
		apierr.Write(w, http.StatusBadRequest, "invalid_request", "authenticated enrollment is POST /api/v1/enroll", nil)
		return
	}
	h.enrollAs(w, r, nil)
}

func (h *Handler) enrollAs(w http.ResponseWriter, r *http.Request, c *service.Caller) {
	var in service.EnrollInput
	if !decode(w, r, &in) {
		return
	}
	e, err := h.svc.Enroll(r.Context(), c, in)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSONRaw(w, http.StatusAccepted, e)
}

func (h *Handler) pollEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PollToken string `json:"poll_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	e, got, err := h.svc.PollEnrollment(r.Context(), r.PathValue("id"), in.PollToken)
	if err != nil {
		fail(w, err)
		return
	}
	if got == nil {
		writeJSONRaw(w, http.StatusOK, e)
		return
	}
	writeJSONRaw(w, http.StatusOK, map[string]any{"enrollment_id": e.ID, "status": e.Status, "sub": got.Sub, "kind": got.Kind,
		"refresh_token": got.RefreshToken, "refresh_expires_at": got.RefreshExpiresAt, "family": got.Family})
}

func (h *Handler) deviceCode(w http.ResponseWriter, r *http.Request) {
	v, err := tokenParams(r)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unreadable request")
		return
	}
	d, err := h.svc.DeviceAuthorize(r.Context(), service.DeviceInput{Sub: v.Get("client_id"), Kind: v.Get("kind"), Display: v.Get("display")})
	if err != nil {
		oauthFail(w, err)
		return
	}
	writeJSONRaw(w, http.StatusOK, d)
}

// deviceInfo is the default verification_uri: Warden builds no approval UI, so it tells the person where the
// decision is made.
func (h *Handler) deviceInfo(w http.ResponseWriter, r *http.Request) {
	writeJSONRaw(w, http.StatusOK, map[string]any{
		"user_code": r.URL.Query().Get("user_code"),
		"message":   "Approve this sign-in from the Gatecrasher card sent to the owner, or with: warden device approve <user_code>",
	})
}
