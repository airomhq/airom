package huggingface

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestHF_CompileLlama3AIBOM(t *testing.T) {
	connector := NewConnector()

	spec := HFModelCardSpec{
		RepoID:         "meta-llama/Meta-Llama-3.1-8B-Instruct",
		Author:         "meta-llama",
		ModelName:      "Meta-Llama-3.1-8B-Instruct",
		License:        "llama3.1",
		PipelineTag:    "text-generation",
		ParameterCount: "8.03B",
		GGUFVariants:   []string{"Q4_K_M", "Q8_0"},
	}

	res := connector.CompileAIBOM(spec)
	if res.Inventory == nil || len(res.Inventory.Components) != 3 {
		t.Fatalf("expected 3 components (1 base + 2 GGUFs), got: %d", len(res.Inventory.Components))
	}

	if len(res.Inventory.Relationships) != 2 {
		t.Fatalf("expected 2 RelUses relationships, got: %d", len(res.Inventory.Relationships))
	}

	if res.Inventory.Relationships[0].Type != airom.RelUses {
		t.Errorf("unexpected relationship type: %v", res.Inventory.Relationships[0].Type)
	}
}
