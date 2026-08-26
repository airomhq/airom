package edge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Verifier evaluates compiled edge models against hardware DMA memory and latency bounds.
type Verifier struct {
	mu sync.RWMutex
}

// NewVerifier constructs a new edge NPU memory boundary verifier.
func NewVerifier() *Verifier {
	return &Verifier{}
}

// VerifyModel evaluates an edge NPU binding against hardware safety ceilings.
func (v *Verifier) VerifyModel(binding EdgeModelBinding) EdgeVerificationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()

	now := time.Now().UTC()
	var violations []string

	// 1. SRAM allocation check (must not exceed 32MB standard NPU on-chip tile)
	const maxHardwareSRAM = 32 * 1024 * 1024 // 32MB
	if binding.MemorySpec.MaxSRAMUsageBytes > maxHardwareSRAM {
		violations = append(violations, fmt.Sprintf("CRITICAL: SRAM usage (%d bytes) exceeds 32MB on-chip NPU tile limit", binding.MemorySpec.MaxSRAMUsageBytes))
	}

	// 2. DMA buffer overrun protection
	if !binding.HasRingBufferGuard {
		violations = append(violations, "HIGH: Shared DMA input buffer lacks hardware ring-buffer guard pages (vulnerable to memory corruption)")
	}

	// 3. Zero-copy alignment verification
	if !binding.MemorySpec.ZeroCopyVerified {
		violations = append(violations, "MEDIUM: Zero-copy DMA buffer alignment not cryptographically attested")
	}

	// 4. Real-time deterministic deadline (must be <= 50ms for automotive/edge robotics)
	if binding.MemorySpec.DeterministicDeadlineMs <= 0 || binding.MemorySpec.DeterministicDeadlineMs > 50 {
		violations = append(violations, fmt.Sprintf("HIGH: Inference deadline (%d ms) exceeds 50ms hard real-time safety threshold", binding.MemorySpec.DeterministicDeadlineMs))
	}

	cleanID := sanitizeID(fmt.Sprintf("edge-%s-%s", binding.Platform, binding.ModelName))
	comp := airom.Component{
		ID:         airom.ID(cleanID),
		Kind:       airom.KindLocalModelFile,
		Name:       binding.ModelName,
		Provider:   airom.KnownString(string(binding.Platform)),
		Confidence: 1.0,
		PURL:       fmt.Sprintf("pkg:edge/%s/%s@%s", strings.ToLower(string(binding.Platform)), binding.ModelName, binding.Quantization),
		Props: []airom.KV{
			{Name: "edge.platform", Value: string(binding.Platform)},
			{Name: "edge.quantization", Value: binding.Quantization},
			{Name: "edge.sram_bytes", Value: fmt.Sprintf("%d", binding.MemorySpec.MaxSRAMUsageBytes)},
			{Name: "edge.deadline_ms", Value: fmt.Sprintf("%d", binding.MemorySpec.DeterministicDeadlineMs)},
		},
	}

	return EdgeVerificationResult{
		ModelName:   binding.ModelName,
		Platform:    binding.Platform,
		IsSafe:      len(violations) == 0,
		Violations:  violations,
		Component:   &comp,
		EvaluatedAt: now,
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
