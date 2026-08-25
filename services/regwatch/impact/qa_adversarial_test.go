package impact

import (
	"math"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_AdversarialNegativeAndOverflowParams(t *testing.T) {
	evaluator := NewEvaluator()

	inv := &airom.Inventory{
		Components: []airom.Component{
			{
				ID:   "comp-overflow",
				Kind: airom.KindHostedLLM,
				Model: &airom.ModelFacet{
					ParamCount: airom.KnownInt64(math.MaxInt64),
				},
			},
			{
				ID:   "comp-negative",
				Kind: airom.KindHostedLLM,
				Model: &airom.ModelFacet{
					ParamCount: airom.KnownInt64(-9999999),
				},
			},
		},
	}

	res := evaluator.EvaluateInventory("CA-SB1047", inv)
	if res == nil || res.TotalComponents != 2 {
		t.Fatalf("expected robust evaluation on extreme parameter counts")
	}
}

func TestQA_AdversarialCorruptedKinds(t *testing.T) {
	evaluator := NewEvaluator()

	inv := &airom.Inventory{
		Components: []airom.Component{
			{ID: "c-corrupt", Kind: airom.ComponentKind("NON_EXISTENT_KIND")},
		},
	}

	res := evaluator.EvaluateInventory("BILL-0", inv)
	if res == nil || res.AffectedCount != 0 {
		t.Fatalf("expected 0 affected for corrupted kind")
	}
}
