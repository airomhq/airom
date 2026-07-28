package app

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

// invWithCompliance builds an inventory whose nist-ai-rmf mapping has a gap
// (MEASURE-2.7) and a met (MAP-2.1).
func invWithGap() *airom.Inventory {
	score := 0.0
	return &airom.Inventory{
		Root: "airom:0000000000000000",
		Components: []airom.Component{
			{ID: "airom:0000000000000000", Kind: airom.KindApplication, Name: "app"},
			{ID: "airom:1111111111111111", Kind: airom.KindHostedLLM, Name: "gpt-4o", Confidence: 0.9},
		},
		Compliance: []airom.ComplianceResult{{
			Framework: "nist-ai-rmf", Name: "N", Version: "1.0",
			Controls: []airom.ControlOutcome{
				{ID: "MAP-2.1", Title: "t", State: airom.ControlMet},
				{ID: "MEASURE-2.7", Title: "t", State: airom.ControlGap, Score: &score},
				{ID: "GOVERN-1.1", Title: "t", State: airom.ControlManual},
			},
		}},
	}
}

// TestComplianceGateParse: the compliance selectors parse, and bad ones fail.
func TestComplianceGateParse(t *testing.T) {
	good := []string{
		"compliance", "compliance:gap", "compliance:nist-ai-rmf",
		"compliance:nist-ai-rmf:MEASURE-2.7", "compliance:gap | hosted-llm",
	}
	for _, e := range good {
		if _, err := ParsePolicy(e); err != nil {
			t.Errorf("ParsePolicy(%q) errored: %v", e, err)
		}
	}
	bad := map[string]string{
		"compliance:nope":               "unknown framework",
		"compliance:nist-ai-rmf:BOGUS":  "unknown control",
		"compliance:gap & hosted-llm":   "mixing rejected",
		"compliance:nist-ai-rmf & risk": "mixing rejected",
	}
	for e, why := range bad {
		if _, err := ParsePolicy(e); err == nil {
			t.Errorf("ParsePolicy(%q) should fail (%s)", e, why)
		}
	}
}

// TestComplianceGateMatches: the gate fires on a GAP only.
func TestComplianceGateMatches(t *testing.T) {
	inv := invWithGap()
	cases := map[string]bool{
		"compliance":                         true,  // any gap
		"compliance:gap":                     true,  // any gap
		"compliance:nist-ai-rmf":             true,  // gap in framework
		"compliance:nist-ai-rmf:MEASURE-2.7": true,  // that control is a gap
		"compliance:nist-ai-rmf:MAP-2.1":     false, // met, not a gap
		"compliance:nist-ai-rmf:GOVERN-1.1":  false, // manual is not a failure
	}
	for expr, want := range cases {
		p, err := ParsePolicy(expr)
		if err != nil {
			t.Fatalf("ParsePolicy(%q): %v", expr, err)
		}
		if got := p.Matches(inv, false); got != want {
			t.Errorf("%q matched=%v, want %v", expr, got, want)
		}
	}
}

// TestComplianceGateNoOverlay: with no compliance overlay, the gate never fires
// (and does not panic).
func TestComplianceGateNoOverlay(t *testing.T) {
	inv := &airom.Inventory{Components: []airom.Component{{ID: "airom:1", Kind: airom.KindHostedLLM}}}
	p, _ := ParsePolicy("compliance:gap")
	if p.Matches(inv, false) {
		t.Error("compliance gate fired with no overlay")
	}
}

// TestReferencesCompliance drives the config guard.
func TestReferencesCompliance(t *testing.T) {
	p, _ := ParsePolicy("compliance:gap | hosted-llm")
	if !p.ReferencesCompliance() {
		t.Error("ReferencesCompliance should be true")
	}
	q, _ := ParsePolicy("hosted-llm&confidence>=0.9")
	if q.ReferencesCompliance() {
		t.Error("ReferencesCompliance should be false")
	}
}
