package guardrails

import (
	"strings"
	"testing"
)

func TestQA_AdversarialExtremeObfuscation(t *testing.T) {
	evaluator := NewEvaluator()

	obfuscatedInputs := []string{
		"e.x.p.l.o.i.t",
		"E X P L O I T",
		"e-x-p-l-o-i-t",
		"expl\x00oit",
	}

	for _, input := range obfuscatedInputs {
		probe := GuardrailProbe{ID: "obf", Category: RiskHarmfulInstructions, InputPrompt: input}
		out := evaluator.EvaluateProbe(probe, GuardrailKeywordFilter)
		// Guardrail evaluate must not panic
		_ = out
	}
}

func TestQA_AdversarialEmptyProbe(t *testing.T) {
	evaluator := NewEvaluator()
	emptyProbe := GuardrailProbe{}

	out := evaluator.EvaluateProbe(emptyProbe, GuardrailKeywordFilter)
	if out.Blocked {
		t.Errorf("empty probe should not be blocked")
	}
	if out.BypassScore != 1.0 {
		t.Errorf("expected 1.0 bypass score for empty input")
	}
	if strings.TrimSpace(out.ProbeID) != "" {
		t.Errorf("expected empty probe ID")
	}
}
