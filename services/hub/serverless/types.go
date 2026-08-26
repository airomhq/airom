// Package serverless discovers, audits, and ingests cloud serverless inference endpoints
// across Groq, Together AI, Cerebras, Fireworks, Replicate, and DeepInfra into canonical AIBOM inventories.
package serverless

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Provider identifies the cloud serverless AI platform.
type Provider string

const (
	ProviderGroq       Provider = "GROQ"
	ProviderTogetherAI Provider = "TOGETHER_AI"
	ProviderCerebras   Provider = "CEREBRAS"
	ProviderFireworks  Provider = "FIREWORKS_AI"
	ProviderReplicate  Provider = "REPLICATE"
	ProviderDeepInfra  Provider = "DEEPINFRA"
)

// EndpointSpec models a discovered serverless model deployment.
type EndpointSpec struct {
	Provider       Provider `json:"provider"`
	ModelName      string   `json:"modelName"`      // e.g. "llama-3.3-70b-versatile"
	HardwareEngine string   `json:"hardwareEngine"` // e.g. "Groq LPU", "Cerebras CS-3", "NVIDIA H100"
	ContextTokens  int      `json:"contextTokens"`  // e.g. 128000
	PricingPerMIn  float64  `json:"pricingPerMIn"`  // USD per million input tokens
	PricingPerMOut float64  `json:"pricingPerMOut"` // USD per million output tokens
	EndpointURL    string   `json:"endpointUrl,omitempty"`
}

// ServerlessAIBOMResult contains the compiled serverless AIBOM inventory.
type ServerlessAIBOMResult struct {
	TotalEndpoints int              `json:"totalEndpoints"`
	Inventory      *airom.Inventory `json:"inventory"`
	IngestedAt     time.Time        `json:"ingestedAt"`
}
