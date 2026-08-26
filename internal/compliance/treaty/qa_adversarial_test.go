package treaty

import (
	"testing"
)

func TestQA_AdversarialNegativeFLOPThreshold(t *testing.T) {
	evaluator := NewEvaluator()

	negSpec := FrontierSafetyCommitments{
		ModelName:              "neg-flops",
		EstimatedFLOPs:         -1e28,
		HasEmergencyKillSwitch: true,
	}

	res := evaluator.EvaluateModel(TreatyBletchleyPark, negSpec)
	if !res.IsConformant {
		t.Fatalf("expected negative FLOP model with kill-switch to evaluate safely")
	}
}

func TestQA_AdversarialMissingKillSwitchSubFrontier(t *testing.T) {
	evaluator := NewEvaluator()

	subSpec := FrontierSafetyCommitments{
		ModelName:              "sub-frontier",
		EstimatedFLOPs:         1e20,
		HasEmergencyKillSwitch: false, // Missing kill switch
	}

	res := evaluator.EvaluateModel(TreatySeoulSummit, subSpec)
	if res.IsConformant {
		t.Fatalf("expected missing emergency kill switch to trigger non-conformance")
	}
}
