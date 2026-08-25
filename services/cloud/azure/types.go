// Package azure provides automated cloud discovery and AIBOM generation
// for Azure AI Studio projects, Azure OpenAI deployments, and enterprise Key Vault bindings.
package azure

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// AzureDeploymentSpec defines an active Azure OpenAI or Azure AI Studio model deployment.
type AzureDeploymentSpec struct {
	DeploymentName     string            `json:"deploymentName"` // e.g. "gpt-4o-prod"
	ModelName          string            `json:"modelName"`      // e.g. "gpt-4o"
	ModelVersion       string            `json:"modelVersion"`   // e.g. "2024-05-13"
	ModelFormat        string            `json:"modelFormat"`    // e.g. "OpenAI"
	CapacityTPM        int64             `json:"capacityTpm"`    // Tokens Per Minute limit
	SubscriptionID     string            `json:"subscriptionId"`
	ResourceGroup      string            `json:"resourceGroup"`
	WorkspaceName      string            `json:"workspaceName"`
	Region             string            `json:"region"` // e.g. "eastus"
	KeyVaultSecretURI  string            `json:"keyVaultSecretUri,omitempty"`
	ContentFilterLevel string            `json:"contentFilterLevel"` // e.g. "Strict", "Default"
	CreatedAt          time.Time         `json:"createdAt"`
	Tags               map[string]string `json:"tags,omitempty"`
}

// DiscoveryScanResult represents the inventory produced by an Azure cloud scan.
type DiscoveryScanResult struct {
	SubscriptionID string                `json:"subscriptionId"`
	TenantID       string                `json:"tenantId"`
	ScannedAt      time.Time             `json:"scannedAt"`
	Deployments    []AzureDeploymentSpec `json:"deployments"`
	Inventory      *airom.Inventory      `json:"inventory"`
}
