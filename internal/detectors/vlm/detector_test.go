package vlm

import (
	"testing"
)

func TestVLM_CompliantPixtralPasses(t *testing.T) {
	detector := NewDetector()

	spec := InferenceSpec{
		Framework:      FrameworkPixtral,
		ModelID:        "mistralai/Pixtral-12B-2409",
		MaxImagePixels: 4 * 1024 * 1024, // 4MP
		HasPromptGuard: true,
	}

	res := detector.EvaluateInference(spec)
	if !res.IsSafe || len(res.Violations) != 0 {
		t.Fatalf("expected safe VLM pipeline, got violations: %+v", res.Violations)
	}

	if res.Component == nil || res.Component.Name != "mistralai/Pixtral-12B-2409" {
		t.Errorf("unexpected component: %+v", res.Component)
	}
}

func TestVLM_UnboundedImagePixelsFails(t *testing.T) {
	detector := NewDetector()

	unsafeSpec := InferenceSpec{
		Framework:      FrameworkQwenVL,
		ModelID:        "Qwen/Qwen2-VL-72B-Instruct",
		MaxImagePixels: 100 * 1024 * 1024, // 100MP (Dangerous DoS risk)
		HasPromptGuard: false,
	}

	res := detector.EvaluateInference(unsafeSpec)
	if res.IsSafe || len(res.Violations) < 2 {
		t.Fatalf("expected unsafe VLM to fail with at least 2 violations, got %d", len(res.Violations))
	}
}
