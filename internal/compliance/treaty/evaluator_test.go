package treaty

import (
	"testing"
)

func TestTreaty_FrontierModelCompliantPasses(t *testing.T) {
	evaluator := NewEvaluator()

	spec := FrontierSafetyCommitments{
		ModelName:                "frontier-nexus-1",
		EstimatedFLOPs:           5e26, // Exceeds 1e26 FLOPs
		HasIndependentRedTeam:    true,
		HasCBRNEvaluation:        true,
		HasCyberOffenseLimits:    true,
		HasEmergencyKillSwitch:   true,
		ResponsibleScalingPolicy: true,
	}

	res := evaluator.EvaluateModel(TreatyBletchleyPark, spec)
	if !res.IsConformant || len(res.Violations) != 0 {
		t.Fatalf("expected conformant frontier model under Bletchley Park, got violations: %+v", res.Violations)
	}
}

func TestTreaty_UnguardedFrontierModelFails(t *testing.T) {
	evaluator := NewEvaluator()

	unsafeSpec := FrontierSafetyCommitments{
		ModelName:             "unguarded-frontier-model",
		EstimatedFLOPs:        2e26,
		HasIndependentRedTeam: false,
		HasCBRNEvaluation:     false,
	}

	res := evaluator.EvaluateModel(TreatySeoulSummit, unsafeSpec)
	if res.IsConformant || len(res.Violations) < 3 {
		t.Fatalf("expected unsafe frontier model to trigger at least 3 treaty violations, got %d", len(res.Violations))
	}
}
