// Package policy sorts a credential request into a tier: ground (auto-approved), elevated (an approver
// agent decides) or critical (the owner decides), or refuses it. The tier comes from a declarative rules
// file, under fixed floors that no rules file can lower. It is exposed as a libs/security/policy PDP, so
// the host evaluates it through policy.Evaluator and every decision is audited.
package policy

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	libpolicy "github.com/hollis-labs/libs/security/policy"
	"gopkg.in/yaml.v3"
)

// Tier is how a request is approved.
type Tier string

const (
	Ground   Tier = "ground"
	Elevated Tier = "elevated"
	Critical Tier = "critical"
	Refused  Tier = "deny"
)

// Action is what a request asks for.
type Action string

const (
	ActionGrant  Action = "grant"  // a grant for an existing principal
	ActionEnroll Action = "enroll" // a new principal and its first parent credential
	ActionDevice Action = "device" // a device-code (RFC 8628) sign-in for an app
)

// Facts are what the host knows about a request, already verified. Nothing here is a caller's claim
// about itself except Purpose (free text, never used to decide).
type Facts struct {
	Action    Action
	Principal string // the sub the credential is for
	Kind      string // its kind
	Requester string // the verified caller's sub ("" for an unauthenticated enrollment)
	// RequesterKind and RequesterAdmin describe the caller; an admin caller is the owner.
	RequesterKind  string
	RequesterAdmin bool
	// ParentOfPrincipal is true when the requester is the recorded parent of the principal (an agent asking
	// for its own session).
	ParentOfPrincipal bool
	Audience          string
	Scopes            []string
	TTL               time.Duration
	// Renewal is true when an existing grant of the same principal and audience already covers the scopes.
	Renewal bool
	// PrincipalExists is true when an enrollment names a principal Warden already knows.
	PrincipalExists bool
}

// Self reports whether the requester asks for itself (or for its own session).
func (f Facts) Self() bool {
	return f.Requester != "" && (f.Requester == f.Principal || f.ParentOfPrincipal)
}

// Verdict is the classification.
type Verdict struct {
	Tier          Tier
	Rule          string // the rule or floor that decided
	Reason        string
	ApproverClass string // elevated only: the approve.<class> an approver must hold
}

// BaseScopes are what every principal holds on Warden itself: read its own state, file requests, use MCP.
var BaseScopes = []string{"warden.mcp", "warden.read", "warden.request"}

// Rule is one entry of the rules file.
type Rule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Actions     []Action `yaml:"actions"`
	Kinds       []string `yaml:"kinds"`
	Audience    string   `yaml:"audience"`
	Scopes      []string `yaml:"scopes"`
	// Verbs, when set, requires every requested scope's verb to be one of them (read, list, ...).
	Verbs         []string      `yaml:"verbs"`
	MaxTTL        time.Duration `yaml:"max_ttl"`
	Self          bool          `yaml:"self"`
	Tier          Tier          `yaml:"tier"`
	ApproverClass string        `yaml:"approver_class"`
}

// Rules is a parsed rules file.
type Rules struct {
	Version int    `yaml:"version"`
	Default Tier   `yaml:"default"`
	Rules   []Rule `yaml:"rules"`
}

//go:embed default-rules.yaml
var defaultRules []byte

// Default returns the embedded starter rules.
func Default() (*Rules, error) { return Parse(defaultRules) }

// Load reads a rules file; an empty path is the embedded default.
func Load(path string) (*Rules, error) {
	if path == "" {
		return Default()
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: an operator-configured path
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse validates a rules document. Unknown keys, tiers and actions are errors.
func Parse(b []byte) (*Rules, error) {
	var r Rules
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("policy: rules: %w", err)
	}
	if r.Version != 1 {
		return nil, errors.New("policy: rules: version must be 1")
	}
	if r.Default == "" {
		r.Default = Critical
	}
	if !validTier(r.Default) || r.Default == Ground {
		return nil, errors.New("policy: rules: default must be elevated, critical or deny")
	}
	seen := map[string]bool{}
	for i, rule := range r.Rules {
		if rule.ID == "" || seen[rule.ID] {
			return nil, fmt.Errorf("policy: rules[%d]: a unique id is required", i)
		}
		seen[rule.ID] = true
		if !validTier(rule.Tier) {
			return nil, fmt.Errorf("policy: rule %s: tier must be ground, elevated, critical or deny", rule.ID)
		}
		if len(rule.Actions) == 0 {
			r.Rules[i].Actions = []Action{ActionGrant}
		}
		for _, a := range r.Rules[i].Actions {
			if a != ActionGrant && a != ActionEnroll && a != ActionDevice {
				return nil, fmt.Errorf("policy: rule %s: unknown action %q", rule.ID, a)
			}
		}
		if rule.Tier == Elevated && rule.ApproverClass == "" {
			r.Rules[i].ApproverClass = "approve.credentials"
		}
	}
	return &r, nil
}

func validTier(t Tier) bool { return t == Ground || t == Elevated || t == Critical || t == Refused }

// Classify applies the floors, then the rules in order (first match wins), then the default.
func (r *Rules) Classify(f Facts) Verdict {
	if v, ok := floor(f); ok {
		return v
	}
	for _, rule := range r.Rules {
		if rule.matches(f) {
			return Verdict{Tier: rule.Tier, Rule: rule.ID, Reason: rule.Description, ApproverClass: rule.ApproverClass}
		}
	}
	v := Verdict{Tier: r.Default, Rule: "default", Reason: "no rule matched"}
	if v.Tier == Elevated {
		v.ApproverClass = "approve.credentials"
	}
	return v
}

func (rule Rule) matches(f Facts) bool {
	if !slices.Contains(rule.Actions, f.Action) {
		return false
	}
	if len(rule.Kinds) > 0 && !slices.Contains(rule.Kinds, f.Kind) {
		return false
	}
	if rule.Audience != "" && rule.Audience != "*" && rule.Audience != f.Audience {
		return false
	}
	if len(rule.Scopes) > 0 && !subset(f.Scopes, rule.Scopes) {
		return false
	}
	for _, s := range f.Scopes {
		if len(rule.Verbs) > 0 && !slices.Contains(rule.Verbs, s[strings.Index(s, ".")+1:]) {
			return false
		}
	}
	if rule.MaxTTL > 0 && (f.TTL <= 0 || f.TTL > rule.MaxTTL) {
		return false
	}
	if rule.Self && !f.Self() {
		return false
	}
	return true
}

// floor holds the owner's fixed rulings (decision 2026-11-19): what is always critical, and what is always
// ground. Rules files cannot lower a critical floor.
func floor(f Facts) (Verdict, bool) {
	crit := func(rule, reason string) (Verdict, bool) {
		return Verdict{Tier: Critical, Rule: "floor:" + rule, Reason: reason}, true
	}
	// The owner's own request is the critical approval itself.
	if f.RequesterAdmin && f.RequesterKind == "human" {
		return Verdict{Tier: Critical, Rule: "floor:owner-direct", Reason: "requested by the owner"}, true
	}
	for _, s := range f.Scopes {
		verb := s[strings.Index(s, ".")+1:]
		if verb == "admin" || strings.HasSuffix(verb, ".admin") || strings.HasPrefix(verb, "admin.") || strings.Contains(s, "*") {
			return crit("admin-scope", "admin or wildcard scope")
		}
		if strings.Contains(verb, "user/") || strings.HasSuffix(verb, ".user") {
			return crit("user-data", "owner (user/*) data")
		}
	}
	if f.Audience == "warden" && !subset(f.Scopes, BaseScopes) {
		return crit("warden-authority", "authority over Warden itself")
	}
	if f.Kind == "human" {
		return crit("human", "credentials for a human principal")
	}
	switch f.Action {
	case ActionDevice:
		return crit("device", "device sign-in is approved by the owner")
	case ActionEnroll:
		if f.PrincipalExists {
			return crit("re-enroll", "a new parent credential for an existing principal")
		}
	case ActionGrant:
		if !f.Self() {
			return crit("other-principal", "credentials for another principal")
		}
		if f.Renewal {
			return Verdict{Tier: Ground, Rule: "floor:renewal", Reason: "renewal inside an existing grant"}, true
		}
	}
	return Verdict{}, false
}

func subset(want, have []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

// PDP adapts Rules to libs/security/policy. Context carries the Facts under "facts". Ground is Allow,
// elevated and critical are Ask with an approval obligation whose reference is "tier:<tier>", deny is Deny.
type PDP struct{ Rules *Rules }

// FactsKey is the policy.Request Context key holding Facts.
const FactsKey = "facts"

// Evaluate implements libpolicy.PDP.
func (p PDP) Evaluate(_ context.Context, req libpolicy.Request) (libpolicy.Decision, error) {
	f, ok := req.Context[FactsKey].(Facts)
	if !ok || p.Rules == nil {
		return libpolicy.Decision{}, errors.New("policy: no facts")
	}
	v := p.Rules.Classify(f)
	match := []libpolicy.PolicyMatch{{ID: v.Rule, Source: "warden-rules", Reason: v.Reason}}
	switch v.Tier {
	case Ground:
		return libpolicy.Decision{Effect: libpolicy.Allow, Reason: "ground", MatchedPolicies: match}, nil
	case Elevated, Critical:
		return libpolicy.Decision{Effect: libpolicy.Ask, Reason: string(v.Tier), MatchedPolicies: match,
			Obligations: []libpolicy.Obligation{{Kind: libpolicy.Approval, PolicyID: v.Rule, Reference: "tier:" + string(v.Tier)}}}, nil
	default:
		return libpolicy.Decision{Effect: libpolicy.Deny, Reason: "deny", MatchedPolicies: match}, nil
	}
}

// TierOf reads the tier back from an evaluated decision.
func TierOf(d libpolicy.Decision) Tier {
	switch d.Effect {
	case libpolicy.Allow:
		return Ground
	case libpolicy.Ask:
		for _, o := range d.Obligations {
			if ref, ok := strings.CutPrefix(o.Reference, "tier:"); ok && o.Kind == libpolicy.Approval {
				return Tier(ref)
			}
		}
		return Critical
	default:
		return Refused
	}
}
