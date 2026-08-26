package serverless

import (
	"testing"
)

func TestQA_AdversarialEmptyServerlessList(t *testing.T) {
	ingestor := NewIngestor()

	res := ingestor.CompileAIBOM(nil)
	if res.TotalEndpoints != 0 || len(res.Inventory.Components) != 0 {
		t.Fatalf("expected 0 components on empty list")
	}
}

func TestQA_AdversarialWeirdModelNamesAndProviders(t *testing.T) {
	ingestor := NewIngestor()

	endpoints := []EndpointSpec{
		{
			Provider:  ProviderReplicate,
			ModelName: "stability-ai/sdxl:39ed52f2a78e934b3ba6e2a89f5b1c712de7dfea535525255b1aa35c5565e08b",
		},
	}

	res := ingestor.CompileAIBOM(endpoints)
	if len(res.Inventory.Components) != 1 {
		t.Fatalf("expected 1 component for complex model name")
	}
}
