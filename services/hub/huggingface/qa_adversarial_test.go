package huggingface

import (
	"fmt"
	"testing"
)

func TestQA_AdversarialEmptyAndCorruptedRepoID(t *testing.T) {
	connector := NewConnector()

	res := connector.CompileAIBOM(HFModelCardSpec{})
	if res.Inventory == nil || len(res.Inventory.Components) != 1 {
		t.Fatalf("expected baseline component on empty spec")
	}
}

func TestQA_AdversarialHugeGGUFVariantList(t *testing.T) {
	connector := NewConnector()

	variants := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		variants[i] = fmt.Sprintf("Q_%d", i)
	}

	spec := HFModelCardSpec{
		RepoID:       "big/model",
		GGUFVariants: variants,
	}

	res := connector.CompileAIBOM(spec)
	if len(res.Inventory.Components) != 1001 {
		t.Fatalf("expected 1001 components, got %d", len(res.Inventory.Components))
	}
}
