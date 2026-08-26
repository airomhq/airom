// Package ollama discovers, inspects, and synchronizes local Ollama model registries into canonical AIBOM inventories.
package ollama

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// OllamaModelSpec models an installed local model extracted from Ollama.
type OllamaModelSpec struct {
	Name              string    `json:"name"`              // e.g. "llama3.1:8b"
	ModelTag          string    `json:"modelTag"`          // e.g. "latest", "8b-instruct-q8_0"
	Digest            string    `json:"digest"`            // sha256 blob digest
	SizeBytes         int64     `json:"sizeBytes"`         // File size on disk
	ParameterSize     string    `json:"parameterSize"`     // e.g. "8.0B"
	QuantizationLevel string    `json:"quantizationLevel"` // e.g. "Q4_0", "Q8_0"
	SystemPrompt      string    `json:"systemPrompt,omitempty"`
	ContextLength     int       `json:"contextLength,omitempty"`
	ModifiedAt        time.Time `json:"modifiedAt"`
}

// OllamaSyncResult contains the synchronized local models and generated AIBOM.
type OllamaSyncResult struct {
	Endpoint     string           `json:"endpoint"` // e.g. "http://localhost:11434"
	TotalModels  int              `json:"totalModels"`
	Inventory    *airom.Inventory `json:"inventory"`
	Synchronized time.Time        `json:"synchronized"`
}
