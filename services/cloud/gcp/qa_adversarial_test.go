package gcp

import (
	"strings"
	"testing"
)

func TestQA_AdversarialGCPNamesAndLabels(t *testing.T) {
	connector := NewConnector()

	endpoints := []VertexEndpointSpec{
		{
			EndpointID:         "projects/123/locations/us-central1/endpoints/'; DROP TABLE endpoints; --",
			DisplayName:        "<script>alert('xss')</script>",
			ModelResourceName:  "publishers/google/models/gemini/../../../../etc/passwd",
			ArtifactGCSURI:     "gs://bucket/\x00\xff/malicious-payload",
			ModelArmorFilterID: "filter-overflow-999999999999999999999999999999999",
			Location:           "us-central1",
		},
	}

	res := connector.CompileAIBOM("proj-evil", "us-central1", endpoints)
	if res == nil || len(res.Inventory.Components) != 2 {
		t.Fatalf("expected 2 components on adversarial inputs")
	}

	for _, c := range res.Inventory.Components {
		if strings.Contains(string(c.ID), " ") || strings.Contains(string(c.ID), ";") {
			t.Errorf("ID was not properly sanitized: %s", c.ID)
		}
	}
}

func TestQA_AdversarialMalformedLocations(t *testing.T) {
	connector := NewConnector()
	endpoints := []VertexEndpointSpec{
		{DisplayName: "ep-unknown", Location: "mars-west-1-deep-space"},
	}

	res := connector.CompileAIBOM("proj-0", "mars-west-1", endpoints)
	if res == nil || len(res.Inventory.Components) != 1 {
		t.Fatalf("expected valid compilation on non-standard location")
	}
}
