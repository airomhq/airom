package vlm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Detector discovers and evaluates multi-modal vision and audio inference pipelines.
type Detector struct {
	mu sync.RWMutex
}

// NewDetector constructs a new VLM and audio framework detector.
func NewDetector() *Detector {
	return &Detector{}
}

// EvaluateInference checks multi-modal pipeline constraints against memory explosion and injection vulnerabilities.
func (d *Detector) EvaluateInference(spec InferenceSpec) SafetyVerdict {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now().UTC()
	var violations []string

	// 1. Image Resolution Clamp (prevent decompression memory bomb DoS)
	const maxSafePixels = 16 * 1024 * 1024 // 16 MegaPixels
	if strings.Contains(string(spec.Framework), "PIXTRAL") || strings.Contains(string(spec.Framework), "QWEN") {
		if spec.MaxImagePixels > maxSafePixels {
			violations = append(violations, fmt.Sprintf("HIGH: Max image pixel limit (%d) exceeds 16MP safety ceiling (vulnerable to image decompression DoS)", spec.MaxImagePixels))
		}
		if !spec.HasPromptGuard {
			violations = append(violations, "MEDIUM: Vision pipeline lacks OCR visual prompt injection guardrails")
		}
	}

	// 2. Audio Duration Bounds
	if strings.Contains(string(spec.Framework), "AUDIO") || strings.Contains(string(spec.Framework), "TTS") || strings.Contains(string(spec.Framework), "VOICE") {
		if spec.MaxAudioDurationSec > 300 {
			violations = append(violations, fmt.Sprintf("HIGH: Audio input duration (%d sec) exceeds 300s limit without chunked streaming", spec.MaxAudioDurationSec))
		}
	}

	cleanID := sanitizeID(fmt.Sprintf("vlm-%s-%s", spec.Framework, spec.ModelID))
	comp := airom.Component{
		ID:         airom.ID(cleanID),
		Kind:       airom.KindHostedLLM,
		Name:       spec.ModelID,
		Provider:   airom.KnownString(string(spec.Framework)),
		Confidence: 0.90,
		PURL:       fmt.Sprintf("pkg:vlm/%s/%s@1.0", strings.ToLower(string(spec.Framework)), spec.ModelID),
		Props: []airom.KV{
			{Name: "vlm.framework", Value: string(spec.Framework)},
			{Name: "vlm.max_pixels", Value: fmt.Sprintf("%d", spec.MaxImagePixels)},
			{Name: "vlm.max_audio_sec", Value: fmt.Sprintf("%d", spec.MaxAudioDurationSec)},
			{Name: "vlm.prompt_guard", Value: fmt.Sprintf("%v", spec.HasPromptGuard)},
		},
	}

	return SafetyVerdict{
		Framework:   spec.Framework,
		ModelID:     spec.ModelID,
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
