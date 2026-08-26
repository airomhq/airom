package huggingface

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Connector compiles remote HuggingFace Hub metadata into canonical AIBOM inventories.
type Connector struct {
	mu sync.RWMutex
}

// NewConnector constructs a new HuggingFace Hub metadata connector.
func NewConnector() *Connector {
	return &Connector{}
}

// CompileAIBOM transforms HuggingFace model card specs into standard airom.Component and airom.Inventory.
func (c *Connector) CompileAIBOM(spec HFModelCardSpec) HFHubAIBOMResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now().UTC()
	var components []airom.Component
	var relationships []airom.Relationship

	cleanID := sanitizeID("hf-" + spec.RepoID)
	primaryComp := airom.Component{
		ID:         airom.ID(cleanID),
		Kind:       airom.KindLocalModelFile,
		Name:       spec.ModelName,
		Provider:   airom.KnownString("HuggingFace"),
		Confidence: 1.0,
		PURL:       fmt.Sprintf("pkg:huggingface/%s@%s", spec.RepoID, spec.ParameterCount),
		Licenses:   []airom.License{{Name: spec.License}},
		Props: []airom.KV{
			{Name: "hf.repo_id", Value: spec.RepoID},
			{Name: "hf.author", Value: spec.Author},
			{Name: "hf.pipeline_tag", Value: spec.PipelineTag},
			{Name: "hf.params", Value: spec.ParameterCount},
		},
	}
	components = append(components, primaryComp)

	// GGUF Quantization Variants
	for _, quant := range spec.GGUFVariants {
		qID := sanitizeID(fmt.Sprintf("hf-%s-gguf-%s", spec.RepoID, quant))
		qComp := airom.Component{
			ID:         airom.ID(qID),
			Kind:       airom.KindLocalModelFile,
			Name:       fmt.Sprintf("%s.gguf", quant),
			Provider:   airom.KnownString("HuggingFace-GGUF"),
			Confidence: 0.95,
			PURL:       fmt.Sprintf("pkg:huggingface/%s/gguf@%s", spec.RepoID, quant),
			Licenses:   []airom.License{{Name: spec.License}},
			Props: []airom.KV{
				{Name: "hf.quantization", Value: quant},
				{Name: "hf.parent_repo", Value: spec.RepoID},
			},
		}
		components = append(components, qComp)
		relationships = append(relationships, airom.Relationship{
			From: airom.ID(cleanID),
			To:   airom.ID(qID),
			Type: airom.RelUses,
		})
	}

	return HFHubAIBOMResult{
		RepoID: spec.RepoID,
		Inventory: &airom.Inventory{
			Components:    components,
			Relationships: relationships,
		},
		DiscoveredAt: now,
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
