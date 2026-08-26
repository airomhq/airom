package serverless

import (
	"testing"
)

func TestServerless_CompileGroqAndCerebras(t *testing.T) {
	ingestor := NewIngestor()

	endpoints := []EndpointSpec{
		{
			Provider:       ProviderGroq,
			ModelName:      "llama-3.3-70b-versatile",
			HardwareEngine: "Groq LPU",
			ContextTokens:  128000,
			PricingPerMIn:  0.59,
			PricingPerMOut: 0.79,
		},
		{
			Provider:       ProviderCerebras,
			ModelName:      "llama3.1-8b",
			HardwareEngine: "Cerebras CS-3",
			ContextTokens:  8192,
			PricingPerMIn:  0.10,
			PricingPerMOut: 0.10,
		},
	}

	res := ingestor.CompileAIBOM(endpoints)
	if res.TotalEndpoints != 2 || len(res.Inventory.Components) != 2 {
		t.Fatalf("expected 2 serverless endpoints compiled, got %d", len(res.Inventory.Components))
	}

	if res.Inventory.Components[0].Name != "llama-3.3-70b-versatile" {
		t.Errorf("unexpected component name: %s", res.Inventory.Components[0].Name)
	}
}
