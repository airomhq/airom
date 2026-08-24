package agentic

import (
	"strings"
	"testing"
	"time"
)

func TestQA_AdversarialUnicodeAndHomoglyphs(t *testing.T) {
	evaluator := NewEvaluator()
	payload := AttackPayload{ID: "p-homoglyph", Vector: VectorPromptInjection}

	homoglyphResponses := []string{
		"I \u200Bcannot comply with this request",          // Zero-width space
		"I саnnot fulfill this (Cyrillic a)",               // Cyrillic homoglyph
		"\u202E!noisivid tseuqer ym ylpmoc tonnaC I\u202C", // RTL override
		"I c a n n o t a s s i s t",                        // Spaced characters
	}

	for i, resp := range homoglyphResponses {
		res := evaluator.EvaluateResponse(payload, resp, 10*time.Millisecond)
		// Evaluator must not crash on adversarial unicode
		if res.PayloadID != payload.ID {
			t.Errorf("case %d failed payload ID match", i)
		}
	}
}

func TestQA_AdversarialExtremePromptSizes(t *testing.T) {
	fuzzer := NewFuzzer()
	evaluator := NewEvaluator()

	hugeTarget := strings.Repeat("adversarial_target_string_", 5000) // 125 KB
	payload := fuzzer.GenerateCrescendoAttack(hugeTarget)

	if len(payload.RawPrompt) < 100000 {
		t.Fatalf("expected >100KB payload")
	}

	res := evaluator.EvaluateResponse(payload, "I cannot fulfill this request.", 10*time.Millisecond)
	if res.Success {
		t.Fatalf("expected refusal")
	}
}

func TestQA_AdversarialEmptyInputs(t *testing.T) {
	evaluator := NewEvaluator()

	emptyPayload := AttackPayload{}
	res := evaluator.EvaluateResponse(emptyPayload, "", 0)

	// An empty response does not contain refusal markers, but should be handled cleanly
	if res.PayloadID != "" {
		t.Errorf("expected empty payload ID")
	}
}
