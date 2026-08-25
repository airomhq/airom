package impact

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestImpact_FrontierModelTriggered(t *testing.T) {
	evaluator := NewEvaluator()

	inv := &airom.Inventory{
		Components: []airom.Component{
			{
				ID:   "comp-llama3-70b",
				Kind: airom.KindHostedLLM,
				Name: "meta-llama/Llama-3-70B-Instruct",
				Model: &airom.ModelFacet{
					ParamCount: airom.KnownInt64(70_000_000_000),
				},
			},
		},
	}

	res := evaluator.EvaluateInventory("CA-SB1047", inv)
	if res == nil || res.TotalComponents != 1 {
		t.Fatalf("expected 1 total component in assessment")
	}

	if res.HighestRisk != RiskCritical {
		t.Errorf("expected RiskCritical, got %s", res.HighestRisk)
	}

	if res.AffectedCount < 1 {
		t.Errorf("expected at least 1 affected component")
	}
}

func TestImpact_EmptyInventory(t *testing.T) {
	evaluator := NewEvaluator()
	res := evaluator.EvaluateInventory("MA-H4887", nil)
	if res == nil || res.TotalComponents != 0 || res.AffectedCount != 0 {
		t.Errorf("expected 0 affected on nil inventory")
	}
}
