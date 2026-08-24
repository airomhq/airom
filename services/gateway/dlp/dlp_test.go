package dlp

import (
	"strings"
	"testing"
)

func TestDLP_RedactSSNAndAPIKey(t *testing.T) {
	engine := NewEngine(DLPPolicy{DefaultAction: ActionMask})

	input := "User SSN is 123-45-6789 and API key is sk-1234567890abcdef1234567890abcdef123456."
	res := engine.ScrubText(input)

	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res.Findings))
	}

	if !strings.Contains(res.SanitizedText, "[REDACTED_SSN]") {
		t.Errorf("SSN not redacted: %s", res.SanitizedText)
	}

	if !strings.Contains(res.SanitizedText, "[REDACTED_API_KEY]") {
		t.Errorf("API key not redacted: %s", res.SanitizedText)
	}
}

func TestDLP_LuhnCreditCardValidation(t *testing.T) {
	engine := NewEngine(DLPPolicy{DefaultAction: ActionMask})

	// Valid Luhn test card (4532-0150-0000-0049)
	validCard := "4532-0150-0000-0049"
	resValid := engine.ScrubText("Customer card: " + validCard)
	if len(resValid.Findings) != 1 || !strings.Contains(resValid.SanitizedText, "[REDACTED_CREDIT_CARD]") {
		t.Errorf("valid card not redacted: %s", resValid.SanitizedText)
	}

	// Invalid Luhn card (1111-2222-3333-4441, sum=57)
	invalidCard := "1111-2222-3333-4441"
	resInvalid := engine.ScrubText("Fake digits: " + invalidCard)
	if len(resInvalid.Findings) != 0 {
		t.Errorf("invalid card should not be scrubbed as credit card")
	}
}

func TestDLP_BlockActionPolicy(t *testing.T) {
	engine := NewEngine(DLPPolicy{DefaultAction: ActionBlock})

	input := "Critical secret: sk-1234567890abcdef1234567890abcdef123456"
	res := engine.ScrubText(input)

	if !res.Blocked {
		t.Fatalf("expected request blocked by DLP policy")
	}

	if !strings.Contains(res.SanitizedText, "REQUEST_BLOCKED_BY_DLP_POLICY") {
		t.Errorf("unexpected block message: %s", res.SanitizedText)
	}
}
