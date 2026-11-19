package client

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

// RequestInput is a grant request.
type RequestInput struct {
	Principal   string            `json:"principal,omitempty"`
	Audience    string            `json:"audience"`
	Scopes      []string          `json:"scopes"`
	TTLSeconds  int64             `json:"ttl_seconds,omitempty"`
	Constraints map[string]any    `json:"constraints,omitempty"`
	Purpose     string            `json:"purpose,omitempty"`
	Evidence    map[string]string `json:"evidence,omitempty"`
}

// Request is a request's state.
type Request struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	Principal  string    `json:"principal"`
	Requester  string    `json:"requester,omitempty"`
	Audience   string    `json:"audience,omitempty"`
	Scopes     []string  `json:"scopes,omitempty"`
	Tier       string    `json:"tier"`
	Rule       string    `json:"rule,omitempty"`
	Status     string    `json:"status"`
	ApprovalID string    `json:"approval_id,omitempty"`
	DecidedBy  string    `json:"decided_by,omitempty"`
	GrantID    string    `json:"grant_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Grant is a grant record.
type Grant struct {
	ID         string    `json:"id"`
	Principal  string    `json:"principal"`
	Audience   string    `json:"audience"`
	Scopes     []string  `json:"scopes"`
	Tier       string    `json:"tier"`
	Rule       string    `json:"rule,omitempty"`
	Approver   string    `json:"approver,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
	RevokedAt  time.Time `json:"revoked_at,omitzero"`
}

// CreateRequest files a request.
func (c *Client) CreateRequest(ctx context.Context, in RequestInput) (Request, error) {
	var r Request
	return r, c.postJSON(ctx, "/api/v1/requests", in, true, &r)
}

// GetRequest reads one request (Warden checks Gatecrasher first when it is pending).
func (c *Client) GetRequest(ctx context.Context, id string) (Request, error) {
	var r Request
	return r, c.get(ctx, "/api/v1/requests/"+url.PathEscape(id), &r)
}

// ListRequests lists the caller's requests (all: every request, owner only).
func (c *Client) ListRequests(ctx context.Context, all bool, status string) ([]Request, error) {
	q := url.Values{}
	if all {
		q.Set("all", "true")
	}
	if status != "" {
		q.Set("status", status)
	}
	var out struct {
		Requests []Request `json:"requests"`
	}
	return out.Requests, c.get(ctx, "/api/v1/requests?"+q.Encode(), &out)
}

// WithdrawRequest withdraws a pending request.
func (c *Client) WithdrawRequest(ctx context.Context, id string) (Request, error) {
	var r Request
	return r, c.postJSON(ctx, "/api/v1/requests/"+url.PathEscape(id)+"/withdraw", struct{}{}, true, &r)
}

// ListGrants lists grants (principal "" = the caller).
func (c *Client) ListGrants(ctx context.Context, principal string) ([]Grant, error) {
	var out struct {
		Grants []Grant `json:"grants"`
	}
	return out.Grants, c.get(ctx, "/api/v1/grants?"+url.Values{"principal": {principal}}.Encode(), &out)
}

// RevokeGrant revokes a grant.
func (c *Client) RevokeGrant(ctx context.Context, id, reason string) (Grant, error) {
	var g Grant
	return g, c.postJSON(ctx, "/api/v1/grants/"+url.PathEscape(id)+"/revoke", map[string]string{"reason": reason}, true, &g)
}

// EnrollInput is an enrollment.
type EnrollInput struct {
	Sub        string            `json:"sub"`
	Kind       string            `json:"kind"`
	Display    string            `json:"display,omitempty"`
	Parent     string            `json:"parent,omitempty"`
	Audience   string            `json:"audience,omitempty"`
	Scopes     []string          `json:"scopes,omitempty"`
	TTLSeconds int64             `json:"ttl_seconds,omitempty"`
	Purpose    string            `json:"purpose,omitempty"`
	Evidence   map[string]string `json:"evidence,omitempty"`
}

// Enrollment is an enrollment's state; PollToken is returned once, by Enroll.
type Enrollment struct {
	ID               string    `json:"enrollment_id"`
	RequestID        string    `json:"request_id"`
	Status           string    `json:"status"`
	Tier             string    `json:"tier"`
	PollToken        string    `json:"poll_token,omitempty"`
	Interval         int       `json:"interval"`
	ExpiresAt        time.Time `json:"expires_at"`
	Sub              string    `json:"sub,omitempty"`
	RefreshToken     string    `json:"refresh_token,omitempty"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at,omitzero"`
}

// Enroll files an enrollment. Authenticated (the caller is recorded as requester) when the client has a
// Bearer; otherwise anonymous.
func (c *Client) Enroll(ctx context.Context, in EnrollInput) (Enrollment, error) {
	var e Enrollment
	if c.Bearer != nil {
		return e, c.postJSON(ctx, "/api/v1/enroll", in, true, &e)
	}
	return e, c.postJSON(ctx, "/v1/enroll", in, false, &e)
}

// PollEnrollment checks an enrollment; once approved it carries the first parent credential, once.
func (c *Client) PollEnrollment(ctx context.Context, id, pollToken string) (Enrollment, error) {
	var e Enrollment
	return e, c.postJSON(ctx, "/v1/enroll/"+url.PathEscape(id)+"/poll", map[string]string{"poll_token": pollToken}, false, &e)
}

// ApproveDevice is the owner deciding a device code.
func (c *Client) ApproveDevice(ctx context.Context, userCode string, deny bool) (Request, error) {
	var r Request
	return r, c.postJSON(ctx, "/api/v1/device/approve", map[string]any{"user_code": userCode, "deny": deny}, true, &r)
}

// DevApprovals lists the fake Gatecrasher's pending approvals (approvals.mode fake, owner only).
func (c *Client) DevApprovals(ctx context.Context) (json.RawMessage, error) {
	var out struct {
		Approvals json.RawMessage `json:"approvals"`
	}
	return out.Approvals, c.get(ctx, "/api/v1/dev/approvals", &out)
}

// DevDecide decides a fake approval as the caller.
func (c *Client) DevDecide(ctx context.Context, approvalID, outcome string) error {
	return c.postJSON(ctx, "/api/v1/dev/approvals/"+url.PathEscape(approvalID)+"/decide", map[string]string{"outcome": outcome}, true, nil)
}

// Whoami returns the verified caller as Warden sees it.
func (c *Client) Whoami(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.get(ctx, "/api/v1/whoami", &out)
}
