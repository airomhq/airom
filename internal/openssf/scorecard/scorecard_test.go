package scorecard

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestScorecard_HighTrustModelPasses(t *testing.T) {
	evaluator := NewEvaluator()

	comp := airom.Component{
		ID:   "comp-secure-llama3",
		Kind: airom.KindHostedLLM,
		Name: "meta-llama/Llama-3-8B",
		PURL: "pkg:huggingface/meta-llama/Llama-3-8B@1.0",
		Licenses: []airom.License{
			{SPDXID: "Apache-2.0"},
		},
		Attestations: []airom.AttestationRef{
			{Type: "cosign-bundle", URI: "https://rekor.sigstore.dev/12345"},
		},
		Model: &airom.ModelFacet{
			Card: &airom.ModelCard{
				Metrics: []airom.PerformanceMetric{
					{Type: "MMLU", Value: "68.4"},
				},
			},
		},
	}

	sc := evaluator.EvaluateComponent(comp)
	if !sc.PassingGrade {
		t.Errorf("expected passing grade for high trust model, got score: %f", sc.OverallScore)
	}

	if sc.OverallScore < 8.5 {
		t.Errorf("expected score >= 8.5, got %f", sc.OverallScore)
	}
}

func TestScorecard_VulnerableModelFails(t *testing.T) {
	evaluator := NewEvaluator()

	comp := airom.Component{
		ID:   "comp-vuln-model",
		Kind: airom.KindLocalModelFile,
		Name: "unvetted-pickle-model.pkl",
		Vulnerabilities: []airom.Vulnerability{
			{ID: "CVE-2024-12345", Severity: "CRITICAL"},
		},
	}

	sc := evaluator.EvaluateComponent(comp)
	if sc.PassingGrade {
		t.Errorf("expected failing grade for vulnerable model, got score: %f", sc.OverallScore)
	}
}
