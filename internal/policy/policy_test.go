package policy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hollis-labs/warden/internal/policy"
)

func TestDefaultRulesParse(t *testing.T) {
	if _, err := policy.Default(); err != nil {
		t.Fatal(err)
	}
}

// A rules file cannot lower the fixed floors: even a rule that marks everything ground leaves admin
// scopes, other principals, humans and device sign-in critical.
func TestFloorsBeatRules(t *testing.T) {
	r, err := policy.Parse([]byte("version: 1\ndefault: elevated\nrules:\n  - id: everything\n    actions: [grant, enroll, device]\n    tier: ground\n"))
	if err != nil {
		t.Fatal(err)
	}
	self := policy.Facts{Action: policy.ActionGrant, Principal: "agent:a", Kind: "agent", Requester: "agent:a", Audience: "torque"}
	cases := map[string]policy.Facts{
		"admin":          withScopes(self, "torque.admin"),
		"wildcard":       withScopes(self, "torque.*"),
		"user data":      withScopes(self, "tesseract.user/chrispian"),
		"warden power":   {Action: policy.ActionGrant, Principal: "agent:a", Kind: "agent", Requester: "agent:a", Audience: "warden", Scopes: []string{"warden.admin"}},
		"other":          {Action: policy.ActionGrant, Principal: "agent:b", Kind: "agent", Requester: "agent:a", Audience: "torque", Scopes: []string{"torque.read"}},
		"human":          {Action: policy.ActionEnroll, Principal: "human:x", Kind: "human"},
		"device":         {Action: policy.ActionDevice, Principal: "app:x", Kind: "app"},
		"re-enroll":      {Action: policy.ActionEnroll, Principal: "app:x", Kind: "app", PrincipalExists: true},
		"anonymous self": {Action: policy.ActionGrant, Principal: "agent:a", Kind: "agent", Audience: "torque", Scopes: []string{"torque.read"}},
	}
	for name, f := range cases {
		if v := r.Classify(f); v.Tier != policy.Critical || !strings.HasPrefix(v.Rule, "floor:") {
			t.Errorf("%s: %+v, want a critical floor", name, v)
		}
	}
	if v := r.Classify(withScopes(self, "torque.write")); v.Tier != policy.Ground || v.Rule != "everything" {
		t.Errorf("ordinary request: %+v", v)
	}
}

func withScopes(f policy.Facts, s ...string) policy.Facts { f.Scopes = s; return f }

func TestRuleMatching(t *testing.T) {
	r, _ := policy.Default()
	llm := policy.Facts{Action: policy.ActionGrant, Principal: "app:s", Kind: "app", Requester: "app:s", Audience: "llm-gateway",
		Scopes: []string{"llm-gateway.decide", "llm-gateway.embed"}, TTL: 30 * 24 * time.Hour}
	if v := r.Classify(llm); v.Tier != policy.Ground {
		t.Fatalf("pilot: %+v", v)
	}
	long := llm
	long.TTL = 31 * 24 * time.Hour
	if v := r.Classify(long); v.Tier == policy.Ground {
		t.Fatalf("over max_ttl still ground: %+v", v)
	}
	mixed := llm
	mixed.Scopes = []string{"llm-gateway.decide", "llm-gateway.provider-write"}
	if v := r.Classify(mixed); v.Tier == policy.Ground {
		t.Fatalf("a scope outside the rule rode along: %+v", v)
	}
	enroll := policy.Facts{Action: policy.ActionEnroll, Principal: "app:n", Kind: "app"}
	if v := r.Classify(enroll); v.Tier != policy.Elevated || v.ApproverClass != "approve.enroll" {
		t.Fatalf("enroll: %+v", v)
	}
}

func TestParseRefusesBadRules(t *testing.T) {
	for name, doc := range map[string]string{
		"version":        "version: 2\n",
		"ground default": "version: 1\ndefault: ground\n",
		"unknown key":    "version: 1\nrules:\n  - id: a\n    tier: ground\n    oops: 1\n",
		"bad tier":       "version: 1\nrules:\n  - id: a\n    tier: maybe\n",
		"dup id":         "version: 1\nrules:\n  - id: a\n    tier: ground\n  - id: a\n    tier: ground\n",
		"bad action":     "version: 1\nrules:\n  - id: a\n    tier: ground\n    actions: [mint]\n",
	} {
		if _, err := policy.Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
