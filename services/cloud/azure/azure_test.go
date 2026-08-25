package azure

import (
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func TestAzure_DeploymentAIBOM(t *testing.T) {
	connector := NewConnector()

	deployments := []AzureDeploymentSpec{
		{
			DeploymentName:     "gpt-4o-prod",
			ModelName:          "gpt-4o",
			ModelVersion:       "2024-05-13",
			ModelFormat:        "OpenAI",
			CapacityTPM:        120000,
			SubscriptionID:     "sub-1234-5678",
			ResourceGroup:      "rg-enterprise-ai",
			WorkspaceName:      "ai-hub-eastus",
			Region:             "eastus",
			KeyVaultSecretURI:  "https://kv-enterprise.vault.azure.net/secrets/openai-key",
			ContentFilterLevel: "Strict",
			CreatedAt:          time.Now().UTC(),
		},
	}

	res := connector.CompileAIBOM("sub-1234-5678", "tenant-9999", deployments)
	if res == nil || res.Inventory == nil {
		t.Fatalf("expected non-nil result and inventory")
	}

	if len(res.Inventory.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(res.Inventory.Components))
	}

	comp := res.Inventory.Components[0]
	if comp.Kind != airom.KindHostedLLM || comp.Name != "gpt-4o" {
		t.Errorf("unexpected component: %+v", comp)
	}

	if ver, ok := comp.Version.Value(); !ok || ver != "2024-05-13" {
		t.Errorf("expected version 2024-05-13, got %s", ver)
	}
}

func TestAzure_EmptyDeployments(t *testing.T) {
	connector := NewConnector()
	res := connector.CompileAIBOM("sub-0", "tenant-0", nil)
	if res == nil || len(res.Inventory.Components) != 0 {
		t.Errorf("expected 0 components on empty input")
	}
}
