package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

// TestPolicyMatches locks the gate semantics: OR-of-conjunctions where each
// conjunction must be satisfied by a SINGLE component, the application root is
// excluded, and MatchAny trips on any discovered component. (Phase 10 review,
// api-cli-config finding: the gate was previously never evaluated.)
func TestPolicyMatches(t *testing.T) {
	inv := &airom.Inventory{Components: []airom.Component{
		{Kind: airom.KindApplication, Name: ".", Confidence: 1.0},
		{Kind: airom.KindHostedLLM, Name: "gpt-4.1", Confidence: 0.85},
		{Kind: airom.KindLibrary, Name: "openai", Confidence: 0.95},
		{
			Kind: airom.KindLocalModelFile, Name: "m.pt", Confidence: 0.9,
			Risks: []airom.ArtifactRisk{{ID: airom.RiskPickleImport, Severity: airom.RiskHigh, Detail: []string{"os.system"}}},
		},
		{
			Kind: airom.KindFramework, Name: "langchain", Confidence: 0.95,
			Vulnerabilities: []airom.Vulnerability{
				{ID: "CVE-2024-0001", Severity: airom.VulnHigh, Score: 7.5},
				{ID: "CVE-2024-0002", Severity: airom.VulnMedium, Score: 5.3},
			},
		},
	}}
	rootOnly := &airom.Inventory{Components: []airom.Component{
		{Kind: airom.KindApplication, Name: ".", Confidence: 1.0},
	}}

	mustParse := func(expr string) *Policy {
		p, err := ParsePolicy(expr)
		if err != nil {
			t.Fatalf("ParsePolicy(%q): %v", expr, err)
		}
		return p
	}

	cases := []struct {
		expr string
		inv  *airom.Inventory
		want bool
	}{
		{"hosted-llm", inv, true},
		{"vector-db", inv, false},                    // no such component
		{"hosted-llm&confidence>=0.9", inv, false},   // gpt-4.1 is 0.85
		{"hosted-llm&confidence>=0.8", inv, true},    // gpt-4.1 is 0.85
		{"library&confidence>=0.9", inv, true},       // openai is 0.95
		{"hosted-llm&library", inv, false},           // no single component is both
		{"vector-db|hosted-llm", inv, true},          // OR
		{"pickle-risk", inv, true},                   // deprecated alias for the pickle-import risk
		{"pickle-risk&confidence>=0.95", inv, false}, // the risky model is 0.9
		{"risk", inv, true},                          // any artifact risk
		{"risk:high", inv, true},                     // pickle-import is high severity
		{"risk:medium", inv, false},                  // none at medium
		{"risk:pickle-import", inv, true},            // by catalog slug
		{"vector-db|risk:high", inv, true},           // OR with a risk selector
		{"cve", inv, true},                           // any CVE (langchain has two)
		{"cve:high", inv, true},                      // threshold fires on the high CVE
		{"cve:critical", inv, false},                 // none at critical
		{"cve:medium", inv, true},                    // threshold fires on high AND medium
		{"framework&cve:high", inv, true},            // one component is both
		{"hosted-llm&cve", inv, false},               // gpt-4.1 has no CVE (single-component rule)
		{"confidence>=0.95", inv, true},              // openai
		// "application" is no longer expressible: it is rejected at parse time
		// (TestParsePolicyRejectsUnknownIdentifiers) precisely because it could
		// only ever return false here. The root-never-counts rule itself is
		// still exercised below, via MatchAny against rootOnly.
	}
	for _, tc := range cases {
		if got := mustParse(tc.expr).Matches(tc.inv, false); got != tc.want {
			t.Errorf("Matches(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}

	// MatchAny: any discovered component trips it; a root-only inventory does not.
	if !MatchAny().Matches(inv, false) {
		t.Error("MatchAny should match an inventory with components")
	}
	if MatchAny().Matches(rootOnly, false) {
		t.Error("MatchAny should NOT match a root-only inventory")
	}
	// A nil policy never gates.
	var nilPolicy *Policy
	if nilPolicy.Matches(inv, false) {
		t.Error("nil policy must not match")
	}
}

// TestRunGateEndToEnd is the end-to-end proof the reviewer asked for: a real
// filesystem scan whose assembled inventory is evaluated against the policy,
// with the resolved exit code surfaced via the PolicyExit sentinel (not merely
// Config.Policy != nil).
func TestRunGateEndToEnd(t *testing.T) {
	withoutEmbeddedRules(t)
	root := writeTree(t, map[string]string{
		"app.py": "import openai\nresp = client.chat.completions.create(model=\"gpt-4.1\", temperature=0.2)\n",
	})
	pack := filepath.Join(t.TempDir(), "openai.yaml")
	yaml := `pack: openai
version: 1
rules:
  - id: openai/model-literal
    kind: hosted-llm
    provider: openai
    languages: [python]
    keywords: ["gpt-"]
    pattern: 'model\s*[:=]\s*["''](?P<model>gpt-[\w.\-]+)["'']'
    claim: { name: "${model}" }
    confidence: 0.85
`
	if err := os.WriteFile(pack, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, policy *Policy, exitCode int) error {
		t.Helper()
		var buf bytes.Buffer
		orig := stdout
		stdout = &buf
		t.Cleanup(func() { stdout = orig })
		cfg := &Config{Source: SourceFS, Target: root, RulePaths: []string{pack}, Policy: policy, ExitCode: exitCode}
		return Run(context.Background(), cfg)
	}

	mustParse := func(expr string) *Policy {
		p, err := ParsePolicy(expr)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Matching gate → PolicyExit with the chosen code.
	err := run(t, mustParse("hosted-llm"), 5)
	var pe *PolicyExit
	if !errors.As(err, &pe) {
		t.Fatalf("matching --fail-on: err = %v, want *PolicyExit", err)
	}
	if pe.Code != 5 {
		t.Errorf("PolicyExit.Code = %d, want 5", pe.Code)
	}

	// MatchAny (--exit-code without --fail-on) → PolicyExit with that code.
	err = run(t, MatchAny(), 3)
	if !errors.As(err, &pe) || pe.Code != 3 {
		t.Fatalf("MatchAny --exit-code 3: err = %v, want PolicyExit{3}", err)
	}

	// Non-matching gate (confidence too high) → clean success, no gate.
	if err := run(t, mustParse("hosted-llm&confidence>=0.95"), 5); err != nil {
		t.Errorf("non-matching gate should be nil, got %v", err)
	}

	// No policy → never gates.
	if err := run(t, nil, 0); err != nil {
		t.Errorf("no policy should be nil, got %v", err)
	}
}
