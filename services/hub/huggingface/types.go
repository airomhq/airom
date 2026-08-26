// Package huggingface provides metadata discovery and remote AIBOM compilation
// for HuggingFace Hub models, Safetensors weights, and GGUF quantizations without downloading weight blobs.
package huggingface

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// HFModelCardSpec models the metadata extracted from HuggingFace Hub APIs and README model cards.
type HFModelCardSpec struct {
	RepoID         string            `json:"repoId"`         // e.g. "meta-llama/Meta-Llama-3.1-8B-Instruct"
	Author         string            `json:"author"`         // e.g. "meta-llama"
	ModelName      string            `json:"modelName"`      // e.g. "Meta-Llama-3.1-8B-Instruct"
	License        string            `json:"license"`        // e.g. "llama3.1", "apache-2.0", "mit"
	PipelineTag    string            `json:"pipelineTag"`    // e.g. "text-generation", "image-to-text"
	ParameterCount string            `json:"parameterCount"` // e.g. "8.03B"
	GGUFVariants   []string          `json:"ggufVariants"`   // e.g. ["Q4_K_M", "Q8_0"]
	BaseModel      string            `json:"baseModel"`      // e.g. "meta-llama/Meta-Llama-3.1-8B"
	Tags           []string          `json:"tags"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// HFHubAIBOMResult contains the compiled inventory and component relationships.
type HFHubAIBOMResult struct {
	RepoID       string           `json:"repoId"`
	Inventory    *airom.Inventory `json:"inventory"`
	DiscoveredAt time.Time        `json:"discoveredAt"`
}
