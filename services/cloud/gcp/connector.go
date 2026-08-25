package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Connector scans and translates GCP Vertex AI resources into canonical AIBOM models.
type Connector struct {
	mu sync.RWMutex
}

// NewConnector constructs a new GCP cloud connector.
func NewConnector() *Connector {
	return &Connector{}
}

// CompileAIBOM builds an *airom.Inventory from discovered Vertex AI endpoints.
func (c *Connector) CompileAIBOM(projectID, location string, endpoints []VertexEndpointSpec) *DiscoveryScanResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now().UTC()
	inv := &airom.Inventory{
		SchemaVersion: "1.0",
		Timestamp:     now,
		Source: airom.SourceInfo{
			Kind:   "gcp_cloud",
			Target: fmt.Sprintf("projects/%s/locations/%s", projectID, location),
		},
		Tool: airom.ToolInfo{
			Name:    "airom-gcp-connector",
			Version: "1.0.0",
		},
	}

	var comps []airom.Component
	var rels []airom.Relationship

	for _, ep := range endpoints {
		cleanID := sanitizeID(fmt.Sprintf("gcp-vertex-%s-%s", ep.Location, ep.DisplayName))
		modelName := ep.ModelResourceName
		if modelName == "" {
			modelName = ep.DisplayName
		}

		provider := "Google-VertexAI"
		if strings.Contains(strings.ToLower(modelName), "anthropic") || strings.Contains(strings.ToLower(modelName), "claude") {
			provider = "Anthropic"
		} else if strings.Contains(strings.ToLower(modelName), "meta") || strings.Contains(strings.ToLower(modelName), "llama") {
			provider = "Meta"
		}

		comp := airom.Component{
			ID:         airom.ID(cleanID),
			Kind:       airom.KindHostedLLM,
			Name:       modelName,
			Version:    airom.KnownString(ep.ModelVersionID),
			Provider:   airom.KnownString(provider),
			Confidence: 1.0,
			PURL:       fmt.Sprintf("pkg:gcp-vertex/%s/%s@%s", ep.Location, modelName, ep.ModelVersionID),
			Props: []airom.KV{
				{Name: "gcp.project_id", Value: ep.ProjectID},
				{Name: "gcp.location", Value: ep.Location},
				{Name: "gcp.endpoint_id", Value: ep.EndpointID},
				{Name: "gcp.display_name", Value: ep.DisplayName},
				{Name: "gcp.resources", Value: ep.DedicatedResources},
				{Name: "gcp.cmek_key", Value: ep.CMEKKeyName},
				{Name: "gcp.model_armor", Value: ep.ModelArmorFilterID},
			},
		}

		comps = append(comps, comp)

		// Model artifact relationship if GCS URI exists
		if ep.ArtifactGCSURI != "" {
			artifactID := airom.ID(sanitizeID(fmt.Sprintf("gcs-artifact-%s", ep.ArtifactGCSURI)))
			artifactComp := airom.Component{
				ID:         artifactID,
				Kind:       airom.KindLocalModelFile,
				Name:       ep.ArtifactGCSURI,
				Provider:   airom.KnownString("Google-Cloud-Storage"),
				Confidence: 1.0,
			}
			comps = append(comps, artifactComp)

			rels = append(rels, airom.Relationship{
				From: comp.ID,
				To:   artifactID,
				Type: airom.RelUses,
			})
		}
	}

	inv.Components = comps
	inv.Relationships = rels

	return &DiscoveryScanResult{
		ProjectID: projectID,
		Location:  location,
		ScannedAt: now,
		Endpoints: endpoints,
		Inventory: inv,
	}
}

func sanitizeID(raw string) string {
	h := sha256.Sum256([]byte(raw))
	short := hex.EncodeToString(h[:4])
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, strings.ToLower(raw))
	if len(clean) > 40 {
		clean = clean[:40]
	}
	return fmt.Sprintf("%s-%s", clean, short)
}
