package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Connector scans and translates Azure AI resources into canonical AIBOM models.
type Connector struct {
	mu sync.RWMutex
}

// NewConnector constructs a new Azure cloud connector.
func NewConnector() *Connector {
	return &Connector{}
}

// CompileAIBOM builds an *airom.Inventory from discovered Azure AI deployments.
func (c *Connector) CompileAIBOM(subscriptionID, tenantID string, deployments []AzureDeploymentSpec) *DiscoveryScanResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now().UTC()
	inv := &airom.Inventory{
		SchemaVersion: "1.0",
		Timestamp:     now,
		Source: airom.SourceInfo{
			Kind:   "azure_cloud",
			Target: fmt.Sprintf("/subscriptions/%s/tenants/%s", subscriptionID, tenantID),
		},
		Tool: airom.ToolInfo{
			Name:    "airom-azure-connector",
			Version: "1.0.0",
		},
	}

	var comps []airom.Component

	for _, dep := range deployments {
		cleanID := sanitizeID(fmt.Sprintf("azure-openai-%s-%s", dep.Region, dep.DeploymentName))
		comp := airom.Component{
			ID:         airom.ID(cleanID),
			Kind:       airom.KindHostedLLM,
			Name:       dep.ModelName,
			Version:    airom.KnownString(dep.ModelVersion),
			Provider:   airom.KnownString("Azure-OpenAI"),
			Confidence: 1.0,
			PURL:       fmt.Sprintf("pkg:azure-openai/%s/%s@%s", dep.Region, dep.ModelName, dep.ModelVersion),
			Props: []airom.KV{
				{Name: "azure.subscription", Value: dep.SubscriptionID},
				{Name: "azure.resource_group", Value: dep.ResourceGroup},
				{Name: "azure.workspace", Value: dep.WorkspaceName},
				{Name: "azure.deployment", Value: dep.DeploymentName},
				{Name: "azure.capacity_tpm", Value: strconv.FormatInt(dep.CapacityTPM, 10)},
				{Name: "azure.content_filter", Value: dep.ContentFilterLevel},
				{Name: "azure.keyvault_secret", Value: dep.KeyVaultSecretURI},
			},
		}

		comps = append(comps, comp)
	}

	inv.Components = comps

	return &DiscoveryScanResult{
		SubscriptionID: subscriptionID,
		TenantID:       tenantID,
		ScannedAt:      now,
		Deployments:    deployments,
		Inventory:      inv,
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
