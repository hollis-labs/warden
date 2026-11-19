package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/hollis-labs/libs/security/secrets/tokenfile"

	"github.com/hollis-labs/warden/client"
	"github.com/hollis-labs/warden/internal/scopes"
)

// conn is how a client command reaches a running Warden. Flags live on each command (the root has no
// value flags; see plan).
type conn struct {
	url, credential, tokenFile string
}

func connFlags(cmd *cobra.Command) *conn {
	c := &conn{}
	cmd.Flags().StringVar(&c.url, "url", envOr("WARDEN_URL", "http://127.0.0.1:8080"), "Warden base URL (env WARDEN_URL)")
	cmd.Flags().StringVar(&c.credential, "credential", os.Getenv("WARDEN_CREDENTIAL"),
		"parent credential file (0600); rotated on every use (env WARDEN_CREDENTIAL)")
	cmd.Flags().StringVar(&c.tokenFile, "token-file", os.Getenv("WARDEN_TOKEN_FILE"),
		"bearer token file (0600), e.g. the owner's API key (env WARDEN_TOKEN_FILE)")
	return c
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// client builds the API client. With anonymous, no credential is required.
func (c *conn) client(anonymous bool) (*client.Client, error) {
	cl := &client.Client{BaseURL: c.url}
	switch {
	case c.tokenFile != "":
		path := c.tokenFile
		cl.Bearer = func(context.Context) (string, error) { return tokenfile.Read(path) }
	case c.credential != "":
		m := &client.Minter{Client: &client.Client{BaseURL: c.url}, ParentFile: c.credential, Audience: "warden"}
		var tok string
		var exp time.Time
		cl.Bearer = func(ctx context.Context) (string, error) {
			if tok != "" && time.Until(exp) > 30*time.Second {
				return tok, nil
			}
			t, err := m.MintToken(ctx)
			if err != nil {
				return "", err
			}
			tok, exp = t.AccessToken, t.ExpiresAt
			return tok, nil
		}
	case !anonymous:
		return nil, errors.New("give --credential (a parent credential file) or --token-file (a bearer token file)")
	}
	return cl, nil
}

func printJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func clientCommands() []*cobra.Command {
	return []*cobra.Command{requestCmd(), grantsCmd(), tokenCmd(), enrollCmd(), deviceCmd(), devCmd(), whoamiCmd()}
}

func requestCmd() *cobra.Command {
	var aud, scope, purpose, task, principal string
	var ttl, wait time.Duration
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Request a grant: warden request --audience llm-gateway --scope llm-gateway.decide,llm-gateway.embed",
		Long: "File a credential request with a running Warden. Policy sorts it into a tier: ground is granted at once; " +
			"elevated and critical go to an approver through Gatecrasher. Once granted, your parent credential mints tokens " +
			"for the audience (warden token --audience ...).",
		Args: cobra.NoArgs,
	}
	c := connFlags(cmd)
	cmd.Flags().StringVar(&aud, "audience", "", "one app id (required)")
	cmd.Flags().StringVar(&scope, "scope", "", "comma- or space-separated <audience>.<verb> scopes (required)")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "grant lifetime (default 720h)")
	cmd.Flags().StringVar(&purpose, "purpose", "", "why (shown to the approver)")
	cmd.Flags().StringVar(&task, "task", "", "task id (evidence)")
	cmd.Flags().StringVar(&principal, "principal", "", "your own session (default yourself)")
	cmd.Flags().DurationVar(&wait, "wait", 0, "wait up to this long for a pending request to be decided")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if aud == "" || scope == "" {
			return errors.New("--audience and --scope are required")
		}
		cl, err := c.client(false)
		if err != nil {
			return err
		}
		in := client.RequestInput{Principal: principal, Audience: aud, Scopes: scopes.Split(scope), TTLSeconds: int64(ttl.Seconds()), Purpose: purpose}
		if task != "" {
			in.Evidence = map[string]string{"task_id": task}
		}
		r, err := cl.CreateRequest(cmd.Context(), in)
		if err != nil {
			return err
		}
		for deadline := time.Now().Add(wait); r.Status == "pending" && time.Now().Before(deadline); {
			time.Sleep(3 * time.Second)
			if r, err = cl.GetRequest(cmd.Context(), r.ID); err != nil {
				return err
			}
		}
		return printJSON(cmd, r)
	}
	status := &cobra.Command{Use: "status <id>", Short: "Show a request", Args: cobra.ExactArgs(1)}
	sc := connFlags(status)
	status.RunE = func(cmd *cobra.Command, args []string) error {
		cl, err := sc.client(false)
		if err != nil {
			return err
		}
		r, err := cl.GetRequest(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		return printJSON(cmd, r)
	}
	var all bool
	var st string
	list := &cobra.Command{Use: "list", Short: "List your requests (--all: every request, owner only)", Args: cobra.NoArgs}
	lc := connFlags(list)
	list.Flags().BoolVar(&all, "all", false, "every request (owner)")
	list.Flags().StringVar(&st, "status", "", "only this status")
	list.RunE = func(cmd *cobra.Command, _ []string) error {
		cl, err := lc.client(false)
		if err != nil {
			return err
		}
		rs, err := cl.ListRequests(cmd.Context(), all, st)
		if err != nil {
			return err
		}
		return printJSON(cmd, rs)
	}
	wd := &cobra.Command{Use: "withdraw <id>", Short: "Withdraw a pending request", Args: cobra.ExactArgs(1)}
	wc := connFlags(wd)
	wd.RunE = func(cmd *cobra.Command, args []string) error {
		cl, err := wc.client(false)
		if err != nil {
			return err
		}
		r, err := cl.WithdrawRequest(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		return printJSON(cmd, r)
	}
	cmd.AddCommand(status, list, wd)
	return cmd
}

func grantsCmd() *cobra.Command {
	var principal string
	cmd := &cobra.Command{Use: "grants", Short: "List your grants", Args: cobra.NoArgs}
	c := connFlags(cmd)
	cmd.Flags().StringVar(&principal, "principal", "", "another principal (owner)")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cl, err := c.client(false)
		if err != nil {
			return err
		}
		gs, err := cl.ListGrants(cmd.Context(), principal)
		if err != nil {
			return err
		}
		return printJSON(cmd, gs)
	}
	var reason string
	revoke := &cobra.Command{Use: "revoke <grant-id>", Short: "Revoke a grant (its live tokens are denied)", Args: cobra.ExactArgs(1)}
	rc := connFlags(revoke)
	revoke.Flags().StringVar(&reason, "reason", "", "why")
	revoke.RunE = func(cmd *cobra.Command, args []string) error {
		cl, err := rc.client(false)
		if err != nil {
			return err
		}
		g, err := cl.RevokeGrant(cmd.Context(), args[0], reason)
		if err != nil {
			return err
		}
		return printJSON(cmd, g)
	}
	cmd.AddCommand(revoke)
	return cmd
}

func tokenCmd() *cobra.Command {
	var aud, scope string
	var ttl time.Duration
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Mint an access token from a parent credential (the file is rotated)",
		Args:  cobra.NoArgs,
	}
	c := connFlags(cmd)
	cmd.Flags().StringVar(&aud, "audience", "warden", "audience")
	cmd.Flags().StringVar(&scope, "scope", "", "narrower scopes (default: the grant's)")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "shorter lifetime")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the whole answer (without the next parent credential)")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if c.credential == "" {
			return errors.New("--credential is required")
		}
		var sc []string
		if scope != "" {
			sc = scopes.Split(scope)
		}
		m := &client.Minter{Client: &client.Client{BaseURL: c.url}, ParentFile: c.credential, Audience: aud, Scopes: sc, TTL: ttl}
		t, err := m.MintToken(cmd.Context())
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(cmd, t)
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), t.AccessToken)
		return err
	}
	return cmd
}

func enrollCmd() *cobra.Command {
	var in client.EnrollInput
	var scope, out string
	var wait time.Duration
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a principal and save its first parent credential: warden enroll --sub app:surface --kind app --out FILE",
		Long: "Enroll an agent, session, machine or app. Without a credential the enrollment is anonymous and waits for an " +
			"approver; with the owner's token it is approved at once. The parent credential is written to --out (0600) and " +
			"never printed.",
		Args: cobra.NoArgs,
	}
	c := connFlags(cmd)
	cmd.Flags().StringVar(&in.Sub, "sub", "", "Registry id (required)")
	cmd.Flags().StringVar(&in.Kind, "kind", "app", "agent, session, machine or app")
	cmd.Flags().StringVar(&in.Display, "display", "", "display name")
	cmd.Flags().StringVar(&in.Parent, "parent", "", "a session's agent")
	cmd.Flags().StringVar(&in.Audience, "audience", "", "first grant's audience (optional)")
	cmd.Flags().StringVar(&scope, "scope", "", "first grant's scopes")
	cmd.Flags().StringVar(&in.Purpose, "purpose", "", "why")
	cmd.Flags().StringVar(&out, "out", "", "file for the parent credential (required)")
	cmd.Flags().DurationVar(&wait, "wait", 10*time.Minute, "how long to wait for approval")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if in.Sub == "" || out == "" {
			return errors.New("--sub and --out are required")
		}
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("%s exists; refusing to overwrite a parent credential", out)
		}
		if scope != "" {
			in.Scopes = scopes.Split(scope)
		}
		cl, err := c.client(true)
		if err != nil {
			return err
		}
		e, err := cl.Enroll(cmd.Context(), in)
		if err != nil {
			return err
		}
		poll, id := e.PollToken, e.ID
		fmt.Fprintf(cmd.ErrOrStderr(), "enrollment %s: %s (tier %s, request %s)\n", id, e.Status, e.Tier, e.RequestID)
		pc := &client.Client{BaseURL: c.url}
		for deadline := time.Now().Add(wait); ; {
			e, err = pc.PollEnrollment(cmd.Context(), id, poll)
			if err != nil {
				return err
			}
			if e.RefreshToken != "" {
				if err := tokenfile.Write(out, e.RefreshToken); err != nil {
					return fmt.Errorf("could not save the parent credential: %w", err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "enrolled %s; parent credential saved to %s\n", e.Sub, out)
				return nil
			}
			if e.Status == "refused" {
				return errors.New("the enrollment was refused")
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("still %s after %s; the poll token lived only in this process, so enroll again (with a longer --wait) once an approver is available", e.Status, wait)
			}
			time.Sleep(time.Duration(max(e.Interval, 2)) * time.Second)
		}
	}
	return cmd
}

func deviceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "device", Short: "Device sign-in (RFC 8628)"}
	var deny bool
	approve := &cobra.Command{Use: "approve <user-code>", Short: "Approve (or --deny) a device sign-in as the owner", Args: cobra.ExactArgs(1)}
	c := connFlags(approve)
	approve.Flags().BoolVar(&deny, "deny", false, "refuse it")
	approve.RunE = func(cmd *cobra.Command, args []string) error {
		cl, err := c.client(false)
		if err != nil {
			return err
		}
		r, err := cl.ApproveDevice(cmd.Context(), args[0], deny)
		if err != nil {
			return err
		}
		return printJSON(cmd, r)
	}
	cmd.AddCommand(approve)
	return cmd
}

func devCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "dev", Short: "Development helpers (approvals.mode fake only)"}
	list := &cobra.Command{Use: "approvals", Short: "List the fake Gatecrasher's pending approvals", Args: cobra.NoArgs}
	lc := connFlags(list)
	list.RunE = func(cmd *cobra.Command, _ []string) error {
		cl, err := lc.client(false)
		if err != nil {
			return err
		}
		raw, err := cl.DevApprovals(cmd.Context())
		if err != nil {
			return err
		}
		var v any
		_ = json.Unmarshal(raw, &v)
		return printJSON(cmd, v)
	}
	decide := &cobra.Command{Use: "decide <approval-id> approved|denied", Short: "Decide a fake approval as the owner", Args: cobra.ExactArgs(2)}
	dc := connFlags(decide)
	decide.RunE = func(cmd *cobra.Command, args []string) error {
		cl, err := dc.client(false)
		if err != nil {
			return err
		}
		return cl.DevDecide(cmd.Context(), args[0], args[1])
	}
	cmd.AddCommand(list, decide)
	return cmd
}

func whoamiCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "whoami", Short: "Show the caller as Warden sees it", Args: cobra.NoArgs}
	c := connFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cl, err := c.client(false)
		if err != nil {
			return err
		}
		w, err := cl.Whoami(cmd.Context())
		if err != nil {
			return err
		}
		return printJSON(cmd, w)
	}
	return cmd
}
