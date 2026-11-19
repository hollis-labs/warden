// Package settings reads the app's own "warden" block from the manifest config. The shell modules read
// theirs; this block holds what only this app has.
//
//	warden:
//	  allowed_hosts: []            # extra Host names served (a local TLS proxy forwarding a public name)
//	  public_url: http://127.0.0.1:18212   # how clients reach Warden (discovery metadata)
//	  issuer: ""                   # iss of every token; default public_url
//	  policy_file: ""              # rules file; default the embedded starter rules
//	  verification_uri: ""         # where a person approves a device code; default <public_url>/v1/device
//	  approvals:
//	    mode: fake                 # fake (in-process, dev only), gatecrasher, or off (elevated/critical stay pending)
//	    url: ""                    # Gatecrasher base URL (mode gatecrasher)
//	    jwks_url: ""               # Gatecrasher decision keys; or jwks_file
//	    jwks_file: ""
//	    issuer: gatecrasher        # iss of signed decisions
//	    token_file: ""             # bearer Warden presents to Gatecrasher (0600 token file)
//	    owner: ""                  # Gatecrasher's owner principal id: the only decider of a critical request
package settings

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Key is the name of the config block.
const Key = "warden"

// Approval modes.
const (
	ApprovalsFake        = "fake"
	ApprovalsGatecrasher = "gatecrasher"
	ApprovalsOff         = "off"
)

// Approvals configures the Gatecrasher client.
type Approvals struct {
	Mode      string
	URL       string
	JWKSURL   string
	JWKSFile  string
	Issuer    string
	TokenFile string
	Owner     string
}

// Settings are the parsed block.
type Settings struct {
	AllowedHosts    []string
	PublicURL       string
	Issuer          string
	PolicyFile      string
	VerificationURI string
	Approvals       Approvals
}

// Parse reads the block (nil for a missing one). An unknown key or a bad value is an error naming the key,
// so a typo is found at startup instead of silently turning a protection off.
func Parse(raw any) (Settings, error) {
	s := Settings{PublicURL: "http://127.0.0.1:18212", Approvals: Approvals{Mode: ApprovalsFake, Issuer: "gatecrasher"}}
	if raw != nil {
		block, ok := raw.(map[string]any)
		if !ok {
			return s, fmt.Errorf("%s: the config block must be a map", Key)
		}
		if err := known(Key, block, "allowed_hosts", "public_url", "issuer", "policy_file", "verification_uri", "approvals"); err != nil {
			return s, err
		}
		if v, present := block["allowed_hosts"]; present && v != nil {
			list, ok := v.([]any)
			if !ok {
				return s, fmt.Errorf("%s.allowed_hosts: must be a list of host names", Key)
			}
			for _, item := range list {
				name, ok := item.(string)
				if !ok || strings.TrimSpace(name) == "" {
					return s, fmt.Errorf("%s.allowed_hosts: every entry must be a non-empty string", Key)
				}
				s.AllowedHosts = append(s.AllowedHosts, strings.TrimSpace(name))
			}
		}
		for key, dst := range map[string]*string{"public_url": &s.PublicURL, "issuer": &s.Issuer, "policy_file": &s.PolicyFile,
			"verification_uri": &s.VerificationURI} {
			if err := str(block, Key+"."+key, key, dst); err != nil {
				return s, err
			}
		}
		if v, present := block["approvals"]; present && v != nil {
			a, ok := v.(map[string]any)
			if !ok {
				return s, fmt.Errorf("%s.approvals: must be a map", Key)
			}
			if err := known(Key+".approvals", a, "mode", "url", "jwks_url", "jwks_file", "issuer", "token_file", "owner"); err != nil {
				return s, err
			}
			for key, dst := range map[string]*string{"mode": &s.Approvals.Mode, "url": &s.Approvals.URL, "jwks_url": &s.Approvals.JWKSURL,
				"jwks_file": &s.Approvals.JWKSFile, "issuer": &s.Approvals.Issuer, "token_file": &s.Approvals.TokenFile,
				"owner": &s.Approvals.Owner} {
				if err := str(a, Key+".approvals."+key, key, dst); err != nil {
					return s, err
				}
			}
		}
	}
	s.PublicURL = strings.TrimRight(s.PublicURL, "/")
	if u, err := url.Parse(s.PublicURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return s, fmt.Errorf("%s.public_url: must be an http(s) URL", Key)
	}
	if s.Issuer == "" {
		s.Issuer = s.PublicURL
	}
	if s.VerificationURI == "" {
		s.VerificationURI = s.PublicURL + "/v1/device"
	}
	switch s.Approvals.Mode {
	case ApprovalsFake, ApprovalsOff:
	case ApprovalsGatecrasher:
		if s.Approvals.URL == "" || (s.Approvals.JWKSURL == "" && s.Approvals.JWKSFile == "") {
			return s, fmt.Errorf("%s.approvals: mode gatecrasher needs url and jwks_url or jwks_file", Key)
		}
	default:
		return s, fmt.Errorf("%s.approvals.mode: must be fake, gatecrasher or off", Key)
	}
	return s, nil
}

func known(name string, block map[string]any, keys ...string) error {
	var unknown []string
	for k := range block {
		ok := false
		for _, want := range keys {
			ok = ok || k == want
		}
		if !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("%s: unknown key(s) %s", name, strings.Join(unknown, ", "))
	}
	return nil
}

func str(block map[string]any, name, key string, dst *string) error {
	v, present := block[key]
	if !present || v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("%s: must be a string", name)
	}
	*dst = strings.TrimSpace(s)
	return nil
}
