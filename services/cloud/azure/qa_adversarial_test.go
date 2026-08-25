package azure

import (
	"strings"
	"testing"
)

func TestQA_AdversarialAzureNamesAndURIs(t *testing.T) {
	connector := NewConnector()

	deployments := []AzureDeploymentSpec{
		{
			DeploymentName:    "../../../../windows/system32/cmd.exe",
			ModelName:         "gpt-4o'; DROP TABLE deployments; --",
			WorkspaceName:     "<script>alert(1)</script>",
			KeyVaultSecretURI: "https://evil-phishing.com/steal?token=123",
		},
	}

	res := connector.CompileAIBOM("sub-evil", "tenant-evil", deployments)
	if res == nil || len(res.Inventory.Components) != 1 {
		t.Fatalf("expected robust compilation on adversarial inputs")
	}

	c := res.Inventory.Components[0]
	if strings.Contains(string(c.ID), " ") || strings.Contains(string(c.ID), ";") {
		t.Errorf("ID was not properly sanitized: %s", c.ID)
	}
}

func TestQA_AdversarialNegativeCapacity(t *testing.T) {
	connector := NewConnector()
	deployments := []AzureDeploymentSpec{
		{DeploymentName: "dep-neg", CapacityTPM: -99999999},
	}

	res := connector.CompileAIBOM("sub-0", "tenant-0", deployments)
	if res == nil || len(res.Inventory.Components) != 1 {
		t.Fatalf("expected valid compilation on negative capacity")
	}
}
