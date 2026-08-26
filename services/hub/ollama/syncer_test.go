package ollama

import (
	"testing"
)

func TestOllama_CompileAIBOM(t *testing.T) {
	syncer := NewSyncer()

	models := []OllamaModelSpec{
		{
			Name:              "llama3.1:8b",
			ModelTag:          "latest",
			Digest:            "sha256:abcdef1234567890",
			SizeBytes:         4661224676,
			ParameterSize:     "8.0B",
			QuantizationLevel: "Q4_0",
		},
		{
			Name:              "nomic-embed-text:latest",
			ModelTag:          "latest",
			Digest:            "sha256:9876543210fedcba",
			SizeBytes:         274302450,
			ParameterSize:     "137M",
			QuantizationLevel: "F16",
		},
	}

	res := syncer.CompileAIBOM("http://localhost:11434", models)
	if res.TotalModels != 2 || len(res.Inventory.Components) != 2 {
		t.Fatalf("expected 2 components synchronized, got: %d", len(res.Inventory.Components))
	}

	if res.Inventory.Components[0].Name != "llama3.1:8b" {
		t.Errorf("unexpected component name: %s", res.Inventory.Components[0].Name)
	}
}
