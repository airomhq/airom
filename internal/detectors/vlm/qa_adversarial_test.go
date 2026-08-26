package vlm

import (
	"testing"
)

func TestQA_AdversarialNegativePixelsAndAudio(t *testing.T) {
	detector := NewDetector()

	negSpec := InferenceSpec{
		Framework:           FrameworkWhisper,
		ModelID:             "neg-audio",
		MaxImagePixels:      -100,
		MaxAudioDurationSec: -50,
	}

	res := detector.EvaluateInference(negSpec)
	if res.Component == nil {
		t.Fatalf("expected component returned on negative metrics")
	}
}

func TestQA_AdversarialWeirdModelIDs(t *testing.T) {
	detector := NewDetector()

	weirdSpec := InferenceSpec{
		Framework:      FrameworkQwenVL,
		ModelID:        "org/model:v1.0@sha256:1234567890abcdef",
		MaxImagePixels: 1024 * 1024,
		HasPromptGuard: true,
	}

	res := detector.EvaluateInference(weirdSpec)
	if !res.IsSafe || res.Component == nil {
		t.Fatalf("expected sanitized clean component for complex model ID")
	}
}
