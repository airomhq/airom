package gcp

import (
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func TestGCP_VertexEndpointAIBOM(t *testing.T) {
	connector := NewConnector()

	endpoints := []VertexEndpointSpec{
		{
			EndpointID:         "projects/123456/locations/us-central1/endpoints/7890",
			DisplayName:        "gemini-pro-production",
			ModelResourceName:  "publishers/google/models/gemini-1.5-pro",
			ModelVersionID:     "001",
			DedicatedResources: "n1-standard-16",
			ArtifactGCSURI:     "gs://my-models-bucket/gemini-fine-tune/model.safetensors",
			CMEKKeyName:        "projects/123456/locations/us-central1/keyRings/kr/cryptoKeys/k1",
			ModelArmorFilterID: "policy-anti-jailbreak-v2",
			ProjectID:          "enterprise-gcp-ai",
			Location:           "us-central1",
			CreatedAt:          time.Now().UTC(),
		},
	}

	res := connector.CompileAIBOM("enterprise-gcp-ai", "us-central1", endpoints)
	if res == nil || res.Inventory == nil {
		t.Fatalf("expected non-nil result and inventory")
	}

	// 1 Vertex endpoint + 1 GCS artifact = 2 components
	if len(res.Inventory.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(res.Inventory.Components))
	}

	comp := res.Inventory.Components[0]
	if comp.Kind != airom.KindHostedLLM || comp.Name != "publishers/google/models/gemini-1.5-pro" {
		t.Errorf("unexpected endpoint component: %+v", comp)
	}

	if len(res.Inventory.Relationships) != 1 || res.Inventory.Relationships[0].Type != airom.RelUses {
		t.Errorf("expected 1 RelUses relationship to GCS artifact")
	}
}

func TestGCP_EmptyEndpoints(t *testing.T) {
	connector := NewConnector()
	res := connector.CompileAIBOM("proj-0", "us-central1", nil)
	if res == nil || len(res.Inventory.Components) != 0 {
		t.Errorf("expected 0 components on empty input")
	}
}
