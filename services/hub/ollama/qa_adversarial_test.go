package ollama

import (
	"testing"
)

func TestQA_AdversarialEmptyOllamaList(t *testing.T) {
	syncer := NewSyncer()

	res := syncer.CompileAIBOM("http://localhost:11434", nil)
	if res.TotalModels != 0 || len(res.Inventory.Components) != 0 {
		t.Fatalf("expected 0 components on empty list")
	}
}

func TestQA_AdversarialWeirdOllamaModelNames(t *testing.T) {
	syncer := NewSyncer()

	models := []OllamaModelSpec{
		{
			Name: "registry.example.com/team/custom-llama:v1.0.0-rc1",
		},
	}

	res := syncer.CompileAIBOM("", models)
	if len(res.Inventory.Components) != 1 {
		t.Fatalf("expected 1 component for complex model name")
	}
}
