package scorecard

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_AdversarialEmptyAndCorruptedComponents(t *testing.T) {
	evaluator := NewEvaluator()
	emptyComp := airom.Component{}

	sc := evaluator.EvaluateComponent(emptyComp)
	if sc.OverallScore < 0 || sc.OverallScore > 10.0 {
		t.Errorf("score outside bounded range [0,10]: %f", sc.OverallScore)
	}
}

func TestQA_AdversarialContradictoryClaims(t *testing.T) {
	evaluator := NewEvaluator()

	comp := airom.Component{
		ID:   "c-conflict",
		Kind: airom.KindHostedLLM,
		// Both valid attestation AND critical vulnerabilities
		Attestations: []airom.AttestationRef{
			{Type: "cosign"},
		},
		Vulnerabilities: []airom.Vulnerability{
			{ID: "CVE-2024-9999", Severity: "CRITICAL"},
		},
	}

	sc := evaluator.EvaluateComponent(comp)
	// Passing grade requires >= 7.0; having critical CVE should pull score down
	for _, c := range sc.Checks {
		if c.CheckID == CheckVulnerabilityDisclosure && c.Score > 5.0 {
			t.Errorf("vulnerability check should have penalized score")
		}
	}
}
