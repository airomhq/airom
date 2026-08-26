package serving

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Detector analyzes model serving engine configurations and flags resource exhaustion risks.
type Detector struct {
	mu sync.RWMutex
}

// NewDetector constructs a new serving engine detector.
func NewDetector() *Detector {
	return &Detector{}
}

// EvaluateConfig analyzes a serving configuration against corporate production stability invariants.
func (d *Detector) EvaluateConfig(cfg ServingConfigSpec) ServingSafetyVerdict {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now().UTC()
	var violations []string

	// 1. GPU Memory Utilization Bounds Check (must not exceed 0.95 to prevent CUDA Out-Of-Memory kernel panics)
	if cfg.GPUMemoryUtil > 0.95 {
		violations = append(violations, fmt.Sprintf("CRITICAL: GPU memory utilization (%.2f) exceeds 0.95 ceiling (high CUDA OOM crash risk)", cfg.GPUMemoryUtil))
	} else if cfg.GPUMemoryUtil <= 0.0 {
		violations = append(violations, "HIGH: GPU memory utilization unspecified or non-positive")
	}

	// 2. Unconstrained Context Window Check (must not exceed 128k tokens without KV-cache quantization)
	if cfg.MaxModelLen > 131072 && cfg.KVQuantization == "" {
		violations = append(violations, fmt.Sprintf("HIGH: Context window (%d tokens) exceeds 128k without KV-cache quantization (fp8/int8)", cfg.MaxModelLen))
	}

	// 3. Tensor Parallelism Validations
	if cfg.TensorParallelSize < 1 {
		violations = append(violations, "MEDIUM: Tensor parallel size must be >= 1")
	}

	cleanID := sanitizeID(fmt.Sprintf("serving-%s-%s", cfg.EngineType, cfg.ModelName))
	comp := airom.Component{
		ID:         airom.ID(cleanID),
		Kind:       airom.KindHostedLLM,
		Name:       cfg.ModelName,
		Provider:   airom.KnownString(string(cfg.EngineType)),
		Confidence: 0.95,
		PURL:       fmt.Sprintf("pkg:serving/%s/%s@tp%d", strings.ToLower(string(cfg.EngineType)), cfg.ModelName, cfg.TensorParallelSize),
		Props: []airom.KV{
			{Name: "serving.engine", Value: string(cfg.EngineType)},
			{Name: "serving.tp_size", Value: fmt.Sprintf("%d", cfg.TensorParallelSize)},
			{Name: "serving.gpu_mem_util", Value: fmt.Sprintf("%.2f", cfg.GPUMemoryUtil)},
			{Name: "serving.max_model_len", Value: fmt.Sprintf("%d", cfg.MaxModelLen)},
			{Name: "serving.kv_quant", Value: cfg.KVQuantization},
		},
	}

	return ServingSafetyVerdict{
		EngineType:   cfg.EngineType,
		ModelName:    cfg.ModelName,
		IsConformant: len(violations) == 0,
		Violations:   violations,
		Component:    &comp,
		EvaluatedAt:  now,
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
