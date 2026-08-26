// Package vlm detects multi-modal Vision-Language Models (VLMs) and audio speech pipelines
// including Pixtral, Qwen-VL, Whisper, Bark, XTTS, and Kokoro.
package vlm

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Framework identifies the multi-modal inference architecture.
type Framework string

const (
	FrameworkPixtral Framework = "PIXTRAL"
	FrameworkQwenVL  Framework = "QWEN_VL"
	FrameworkWhisper Framework = "WHISPER_AUDIO"
	FrameworkKokoro  Framework = "KOKORO_TTS"
	FrameworkBark    Framework = "BARK_AUDIO"
	FrameworkXTTS    Framework = "XTTS_VOICE"
)

// InferenceSpec models a multi-modal pipeline configuration.
type InferenceSpec struct {
	Framework           Framework `json:"framework"`
	ModelID             string    `json:"modelId"`             // e.g. "mistralai/Pixtral-12B-2409"
	MaxImagePixels      int64     `json:"maxImagePixels"`      // Image resolution clamp (e.g. 4096*4096)
	MaxAudioDurationSec int       `json:"maxAudioDurationSec"` // Max seconds per request
	HasPromptGuard      bool      `json:"hasPromptGuard"`      // OCR visual prompt injection guard
	SourceLocation      string    `json:"sourceLocation"`
}

// SafetyVerdict models the safety evaluation for a multi-modal deployment.
type SafetyVerdict struct {
	Framework   Framework        `json:"framework"`
	ModelID     string           `json:"modelId"`
	IsSafe      bool             `json:"isSafe"`
	Violations  []string         `json:"violations"`
	Component   *airom.Component `json:"component"`
	EvaluatedAt time.Time        `json:"evaluatedAt"`
}
