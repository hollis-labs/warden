package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient talks to Gatecrasher's approval API.
type HTTPClient struct {
	BaseURL string // e.g. https://gatecrasher.example (no trailing slash)
	// Token returns the bearer Warden presents (a Warden token aud=gatecrasher, or a Gatecrasher API key).
	Token  func(ctx context.Context) (string, error)
	Client *http.Client
}

func (c *HTTPClient) do(ctx context.Context, method, path string, body any, wait time.Duration) (Ticket, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return Ticket{}, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return Ticket{}, errors.New("approval: invalid gatecrasher URL")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != nil {
		tok, xerr := c.Token(ctx)
		if xerr != nil {
			return Ticket{}, fmt.Errorf("approval: credential: %w", xerr)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	hc := c.Client
	if hc == nil {
		hc = &http.Client{Timeout: 15*time.Second + wait}
	}
	resp, err := hc.Do(req) //nolint:gosec // G704: the operator-configured Gatecrasher URL
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // never echo the URL
		}
		return Ticket{}, fmt.Errorf("approval: gatecrasher: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return Ticket{}, fmt.Errorf("approval: gatecrasher refused: status %d", resp.StatusCode)
	}
	var t Ticket
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &t); err != nil {
			return Ticket{}, errors.New("approval: gatecrasher answer is unreadable")
		}
	}
	return t, nil
}

// Submit implements Approver.
func (c *HTTPClient) Submit(ctx context.Context, r Request) (Ticket, error) {
	t, err := c.do(ctx, http.MethodPost, "/api/gate/v1/approvals", r, 0)
	if err == nil && t.ApprovalID == "" {
		return Ticket{}, errors.New("approval: gatecrasher returned no approval id")
	}
	return t, err
}

// Await implements Approver.
func (c *HTTPClient) Await(ctx context.Context, id string, wait time.Duration) (Ticket, error) {
	path := "/api/gate/v1/approvals/" + url.PathEscape(id)
	if wait > 0 {
		path += "/await?timeout=" + url.QueryEscape(wait.String())
	}
	return c.do(ctx, http.MethodGet, path, nil, wait)
}

// Withdraw implements Approver.
func (c *HTTPClient) Withdraw(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodPost, "/api/gate/v1/approvals/"+url.PathEscape(id)+"/withdraw", struct{}{}, 0)
	return err
}
