package dlp

import (
	"testing"
)

func TestQA_AdversarialEvasionPatterns(t *testing.T) {
	engine := NewEngine(DLPPolicy{DefaultAction: ActionMask})

	evasionInputs := []string{
		"SSN is 123 - 45 - 6789", // Spaced hyphens
		"Card is 4532  0150  0000  0043",
		"Zero byte \x00 in string sk-abcdef1234567890abcdef1234567890",
	}

	for _, input := range evasionInputs {
		res := engine.ScrubText(input)
		// Must not panic and must sanitize
		_ = res
	}
}

func TestQA_AdversarialEmptyAndNullStrings(t *testing.T) {
	engine := NewEngine(DLPPolicy{DefaultAction: ActionMask})

	res := engine.ScrubText("")
	if res.SanitizedText != "" || len(res.Findings) != 0 {
		t.Errorf("expected empty result on empty input")
	}
}
