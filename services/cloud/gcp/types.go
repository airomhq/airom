// Package gcp provides automated cloud discovery and AIBOM generation
// for GCP Vertex AI Model Garden endpoints, custom models, and Model Armor security filters.
package gcp

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// VertexEndpointSpec defines an active GCP Vertex AI online serving endpoint.
type VertexEndpointSpec struct {
	EndpointID         string            `json:"endpointId"`                   // e.g. "projects/123456/locations/us-central1/endpoints/789"
	DisplayName        string            `json:"displayName"`                  // e.g. "gemini-1.5-pro-serving"
	ModelResourceName  string            `json:"modelResourceName"`            // e.g. "publishers/google/models/gemini-1.5-pro"
	ModelVersionID     string            `json:"modelVersionId"`               // e.g. "001"
	DedicatedResources string            `json:"dedicatedResources"`           // e.g. "n1-standard-16 + 2x NVIDIA_TESLA_T4"
	ArtifactGCSURI     string            `json:"artifactGcsUri,omitempty"`     // e.g. "gs://my-models/custom-ner/model.joblib"
	CMEKKeyName        string            `json:"cmekKeyName,omitempty"`        // e.g. "projects/p/locations/l/keyRings/r/cryptoKeys/k"
	ModelArmorFilterID string            `json:"modelArmorFilterId,omitempty"` // Model Armor guardrail policy ID
	ProjectID          string            `json:"projectId"`
	Location           string            `json:"location"` // e.g. "us-central1"
	CreatedAt          time.Time         `json:"createdAt"`
	Labels             map[string]string `json:"labels,omitempty"`
}

// DiscoveryScanResult represents the inventory produced by a GCP cloud scan.
type DiscoveryScanResult struct {
	ProjectID string               `json:"projectId"`
	Location  string               `json:"location"`
	ScannedAt time.Time            `json:"scannedAt"`
	Endpoints []VertexEndpointSpec `json:"endpoints"`
	Inventory *airom.Inventory     `json:"inventory"`
}
