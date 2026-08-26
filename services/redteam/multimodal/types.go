// Package multimodal provides adversarial red-teaming evaluation for vision-language models (VLMs),
// audio-speech pipelines, and multi-modal prompt injection attack vectors.
package multimodal

import (
	"time"
)

// AttackVector classifies the multi-modal adversarial injection technique.
type AttackVector string

const (
	VectorTypographicOCR     AttackVector = "VISUAL_TYPOGRAPHIC_INJECTION" // Rendered text instructions embedded in images
	VectorPixelPerturbation  AttackVector = "ADVERSARIAL_PIXEL_MASK"       // High-frequency noise triggering misclassification
	VectorAcousticUltrasound AttackVector = "ULTRASONIC_AUDIO_COMMAND"     // High-frequency voice commands inaudible to humans
	VectorPolyglotSmuggling  AttackVector = "CROSS_MODAL_POLYGLOT"         // Hidden executable payloads disguised as image metadata
)

// MultiModalPayload represents an input image, audio snippet, or document evaluated by the red-team prober.
type MultiModalPayload struct {
	PayloadID     string            `json:"payloadId"`
	MimeType      string            `json:"mimeType"` // e.g. "image/png", "audio/wav"
	RawBytes      []byte            `json:"rawBytes"`
	ExtractedText string            `json:"extractedText,omitempty"` // OCR or STT transcribed content
	SampleRateHz  int               `json:"sampleRateHz,omitempty"`  // Audio sample rate
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// MultiModalVerdict represents the red-team detection outcome.
type MultiModalVerdict struct {
	PayloadID   string       `json:"payloadId"`
	IsMalicious bool         `json:"isMalicious"`
	Vector      AttackVector `json:"vector,omitempty"`
	Confidence  float64      `json:"confidence"` // 0.0 to 1.0
	Details     string       `json:"details"`
	EvaluatedAt time.Time    `json:"evaluatedAt"`
}
