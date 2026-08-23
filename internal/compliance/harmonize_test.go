package compliance

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestHarmonization_GlobalMultiFrameworkEvaluation(t *testing.T) {
	// Inventory with safe LLM and Dataset
	testInv := &airom.Inventory{
		Root: "airom:root",
		Components: []airom.Component{
			{
				ID:   "airom:hosted_gpt4o",
				Kind: airom.KindHostedLLM,
				Name: "openai/gpt-4o",
				Evidence: airom.Evidence{
					Occurrences: []airom.Occurrence{
						{Location: airom.Location{Path: "src/inference.py", Line: 42}},
					},
				},
			},
			{
				ID:   "airom:train_data",
				Kind: airom.KindDataset,
				Name: "customer_support_data",
				Evidence: airom.Evidence{
					Occurrences: []airom.Occurrence{
						{Location: airom.Location{Path: "data/support.jsonl", Line: 1}},
					},
				},
			},
		},
	}

	frameworks := []string{
		"eu-ai-act",
		"colorado-ai-act",
		"iso-42001",
		"canada-aida",
		"nist-ai-rmf",
	}

	results, err := Evaluate(testInv, frameworks, false)
	if err != nil {
		t.Fatalf("Evaluate failed across multi-frameworks: %v", err)
	}

	if len(results) != len(frameworks) {
		t.Fatalf("expected %d framework results, got %d", len(frameworks), len(results))
	}

	harmonized := Harmonize(testInv, results)

	if len(harmonized.FrameworksEvaluated) != 5 {
		t.Errorf("expected 5 frameworks evaluated, got %d", len(harmonized.FrameworksEvaluated))
	}

	if harmonized.TotalControls == 0 {
		t.Error("expected non-zero total controls")
	}

	// Verify Shared Evidence Map links gpt-4o to multiple frameworks
	gpt4Evidence := harmonized.SharedEvidenceMap["airom:hosted_gpt4o"]
	if len(gpt4Evidence) == 0 {
		t.Error("expected gpt-4o to serve as shared evidence across frameworks")
	}

	// Verify Dataset Evidence links customer_support_data
	dataEvidence := harmonized.SharedEvidenceMap["airom:train_data"]
	if len(dataEvidence) == 0 {
		t.Error("expected dataset to serve as shared evidence for data governance")
	}

	// Verify Category Summaries
	invSummary, ok := harmonized.CategorySummaries[CategoryInventoryAndClassification]
	if !ok || invSummary.MetCount == 0 {
		t.Errorf("expected Inventory & Classification category to have Met controls; got %+v", invSummary)
	}

	dataSummary, ok := harmonized.CategorySummaries[CategoryDataGovernance]
	if !ok || dataSummary.MetCount == 0 {
		t.Errorf("expected Data Governance category to have Met controls; got %+v", dataSummary)
	}

	if harmonized.HarmonizedReadiness != 100.0 {
		t.Errorf("expected 100.0%% readiness for clean inventory, got %.2f%%", harmonized.HarmonizedReadiness)
	}
}

func TestHarmonization_CrossJurisdictionGapOverlap(t *testing.T) {
	// Inventory with an unsafe local model file containing a security risk
	riskInv := &airom.Inventory{
		Root: "airom:root",
		Components: []airom.Component{
			{
				ID:   "airom:unsafe_model",
				Kind: airom.KindLocalModelFile,
				Name: "malicious_weights.bin",
				Risks: []airom.ArtifactRisk{
					{
						ID:       airom.RiskUnsafeLoad,
						Severity: airom.RiskHigh,
						Detail:   []string{"Arbitrary code execution via pickle serialization flaw"},
					},
				},
				Evidence: airom.Evidence{
					Occurrences: []airom.Occurrence{
						{Location: airom.Location{Path: "weights/load.py", Line: 99}},
					},
				},
			},
		},
	}

	frameworks := []string{
		"eu-ai-act",
		"iso-42001",
		"canada-aida",
		"nist-ai-rmf",
		"owasp-agentic",
	}

	results, err := Evaluate(riskInv, frameworks, false)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	harmonized := Harmonize(riskInv, results)

	if harmonized.TotalGap == 0 {
		t.Error("expected compliance gaps to be triggered by risk")
	}

	// Verify Cross Jurisdiction Gaps links unsafe_model
	gaps, exists := harmonized.CrossJurisdictionGaps["airom:unsafe_model"]
	if !exists || len(gaps) == 0 {
		t.Errorf("expected unsafe_model in CrossJurisdictionGaps, got %+v", harmonized.CrossJurisdictionGaps)
	}

	// Security & Robustness category should be in GAP state
	secSummary := harmonized.CategorySummaries[CategorySecurityAndRobustness]
	if secSummary.State != airom.ControlGap {
		t.Errorf("expected Security & Robustness category state to be GAP, got %s", secSummary.State)
	}

	if harmonized.HarmonizedReadiness >= 100.0 {
		t.Errorf("expected readiness < 100.0%% due to gaps, got %.2f%%", harmonized.HarmonizedReadiness)
	}
}
