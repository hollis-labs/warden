// Package client is the Go client for Warden: the rotation-aware parent-credential minter apps use to get
// short-lived tokens (it plugs into libs/security/auth's Refresher), and the calls behind the warden CLI.
//
// A parent credential rotates on every use: each refresh returns a new one, and presenting an old one
// revokes the whole family (reuse detection). So the parent lives in exactly one 0600 file, every refresh
// holds an exclusive lock on it, and the new parent is written atomically before the access token is
// returned. Two processes must never share a parent file without sharing the lock (this package's lock).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	libauth "github.com/hollis-labs/libs/security/auth"
	"github.com/hollis-labs/libs/security/secrets/tokenfile"
)

// Client talks to one Warden.
type Client struct {
	BaseURL string // e.g. http://127.0.0.1:18212
	HTTP    *http.Client
	// Bearer returns the credential for the management API (/api/v1/...): a Warden token for audience
	// warden (Minter.Token) or an owner API key.
	Bearer func(ctx context.Context) (string, error)
}

// Error is a refusal from Warden. Code is the OAuth error or the API error code.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s (status %d)", e.Code, e.Status)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// IsCode reports whether err is a Warden refusal with code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, ctype string, auth bool, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, body)
	if err != nil {
		return errors.New("warden: invalid URL")
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if auth {
		if c.Bearer == nil {
			return errors.New("warden: no credential configured")
		}
		tok, xerr := c.Bearer(ctx)
		if xerr != nil {
			return xerr
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.http().Do(req) //nolint:gosec // G704: the configured Warden URL
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // never echo the URL
		}
		return fmt.Errorf("warden: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error            any    `json:"error"`
			ErrorDescription string `json:"error_description"`
			Code             string `json:"code"`
			Message          string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		out := &Error{Status: resp.StatusCode, Code: e.Code, Message: firstNonEmpty(e.ErrorDescription, e.Message)}
		switch v := e.Error.(type) {
		case string:
			out.Code = v
		case map[string]any: // the Substrate flat error body {"error":{"code","message"}}
			if s, ok := v["code"].(string); ok {
				out.Code = s
			}
			if s, ok := v["message"].(string); ok {
				out.Message = s
			}
		}
		if out.Code == "" {
			out.Code = http.StatusText(resp.StatusCode)
		}
		return out
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("warden: unreadable answer")
		}
	}
	return nil
}

func (c *Client) postJSON(ctx context.Context, path string, in any, auth bool, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, bytes.NewReader(b), "application/json", auth, out)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, "", true, out)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Token is /v1/token's answer.
type Token struct {
	AccessToken      string    `json:"access_token"`
	ExpiresAt        time.Time `json:"expires_at"`
	TTL              int       `json:"ttl_seconds"`
	Audience         string    `json:"aud"`
	Scope            string    `json:"scope"`
	Grant            string    `json:"grant"`
	Sub              string    `json:"sub"`
	Kind             string    `json:"kind"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

// Refresh redeems a parent credential for a token. The answer carries the next parent; the old one is spent.
func (c *Client) Refresh(ctx context.Context, parent, audience string, scopes []string, ttl time.Duration) (Token, error) {
	v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {parent}}
	if audience != "" {
		v.Set("audience", audience)
	}
	if len(scopes) > 0 {
		v.Set("scope", strings.Join(scopes, " "))
	}
	if ttl > 0 {
		v.Set("ttl_seconds", strconv.Itoa(int(ttl.Seconds())))
	}
	var t Token
	err := c.do(ctx, http.MethodPost, "/v1/token", strings.NewReader(v.Encode()), "application/x-www-form-urlencoded", false, &t)
	return t, err
}

// Minter mints tokens for one audience from a parent-credential file, rotating the file on every use.
type Minter struct {
	Client     *Client
	ParentFile string
	Audience   string
	Scopes     []string
	TTL        time.Duration
}

// Mint implements libauth.MintFunc: use it as RefresherConfig.Mint.
func (m *Minter) Mint(ctx context.Context) (libauth.Issued, error) {
	t, err := m.MintToken(ctx)
	if err != nil {
		return libauth.Issued{}, err
	}
	return libauth.Issued{Token: t.AccessToken, ExpiresAt: t.ExpiresAt}, nil
}

// MintToken mints and returns the full answer (the next parent is already saved).
func (m *Minter) MintToken(ctx context.Context) (Token, error) {
	unlock, err := lockFile(m.ParentFile + ".lock")
	if err != nil {
		return Token{}, fmt.Errorf("warden: lock parent credential: %w", err)
	}
	defer unlock()
	parent, err := tokenfile.Read(m.ParentFile)
	if err != nil {
		return Token{}, fmt.Errorf("warden: parent credential: %w", err)
	}
	t, err := m.Client.Refresh(ctx, parent, m.Audience, m.Scopes, m.TTL)
	if err != nil {
		return Token{}, err
	}
	if t.RefreshToken == "" {
		return Token{}, errors.New("warden: the token answer carries no next parent credential")
	}
	if err := tokenfile.Write(m.ParentFile, t.RefreshToken); err != nil {
		// The old parent is spent and the new one could not be saved: the caller must re-enroll.
		return Token{}, fmt.Errorf("warden: could not save the rotated parent credential (re-enroll): %w", err)
	}
	t.RefreshToken = ""
	return t, nil
}

// Refresher builds a libs auth Refresher over the minter (renews at two thirds of each token's life).
func (m *Minter) Refresher() (*libauth.Refresher, error) {
	return libauth.NewRefresher(libauth.RefresherConfig{Mint: m.Mint})
}
