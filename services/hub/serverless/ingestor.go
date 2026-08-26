package serverless

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Ingestor compiles serverless AI endpoints into standard AIBOM inventories.
type Ingestor struct {
	mu sync.RWMutex
}

// NewIngestor constructs a new serverless AI ingestor.
func NewIngestor() *Ingestor {
	return &Ingestor{}
}

// CompileAIBOM transforms serverless endpoints into canonical airom.Inventory.
func (in *Ingestor) CompileAIBOM(endpoints []EndpointSpec) ServerlessAIBOMResult {
	in.mu.RLock()
	defer in.mu.RUnlock()

	now := time.Now().UTC()
	components := make([]airom.Component, 0, len(endpoints))

	for _, ep := range endpoints {
		cleanID := sanitizeID(fmt.Sprintf("serverless-%s-%s", ep.Provider, ep.ModelName))
		comp := airom.Component{
			ID:         airom.ID(cleanID),
			Kind:       airom.KindHostedLLM,
			Name:       ep.ModelName,
			Provider:   airom.KnownString(string(ep.Provider)),
			Confidence: 1.0,
			PURL:       fmt.Sprintf("pkg:serverless/%s/%s@1.0", strings.ToLower(string(ep.Provider)), ep.ModelName),
			Props: []airom.KV{
				{Name: "serverless.provider", Value: string(ep.Provider)},
				{Name: "serverless.hardware", Value: ep.HardwareEngine},
				{Name: "serverless.context_tokens", Value: fmt.Sprintf("%d", ep.ContextTokens)},
				{Name: "serverless.price_in", Value: fmt.Sprintf("%.4f", ep.PricingPerMIn)},
				{Name: "serverless.price_out", Value: fmt.Sprintf("%.4f", ep.PricingPerMOut)},
			},
		}
		components = append(components, comp)
	}

	return ServerlessAIBOMResult{
		TotalEndpoints: len(endpoints),
		Inventory: &airom.Inventory{
			Components: components,
		},
		IngestedAt: now,
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
