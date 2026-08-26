package ollama

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Syncer compiles local Ollama model tags into canonical AIBOM components.
type Syncer struct {
	mu sync.RWMutex
}

// NewSyncer constructs a new Ollama model synchronizer.
func NewSyncer() *Syncer {
	return &Syncer{}
}

// CompileAIBOM converts Ollama model specifications into canonical airom.Inventory.
func (s *Syncer) CompileAIBOM(endpoint string, models []OllamaModelSpec) OllamaSyncResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}

	components := make([]airom.Component, 0, len(models))
	for _, m := range models {
		cleanID := sanitizeID("ollama-" + m.Name)
		comp := airom.Component{
			ID:         airom.ID(cleanID),
			Kind:       airom.KindLocalModelFile,
			Name:       m.Name,
			Provider:   airom.KnownString("Ollama"),
			Confidence: 1.0,
			PURL:       fmt.Sprintf("pkg:ollama/%s@%s", m.Name, m.QuantizationLevel),
			Props: []airom.KV{
				{Name: "ollama.digest", Value: m.Digest},
				{Name: "ollama.size_bytes", Value: fmt.Sprintf("%d", m.SizeBytes)},
				{Name: "ollama.param_size", Value: m.ParameterSize},
				{Name: "ollama.quantization", Value: m.QuantizationLevel},
			},
		}
		components = append(components, comp)
	}

	return OllamaSyncResult{
		Endpoint:    endpoint,
		TotalModels: len(models),
		Inventory: &airom.Inventory{
			Components: components,
		},
		Synchronized: now,
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
