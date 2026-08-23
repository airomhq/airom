package gateway

import (
	"strings"
	"testing"
)

func TestRedactor_SecretsAndPII(t *testing.T) {
	r := NewRedactor()

	input := "User John Doe (john.doe@example.com) with SSN 123-45-6789 used AWS Key AKIAIOSFODNN7EXAMPLE and OpenAI Key sk-proj-1234567890abcdefghijklmn to purchase."
	redacted := r.RedactText(input)

	if strings.Contains(redacted, "john.doe@example.com") {
		t.Errorf("email was not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED:EMAIL]") {
		t.Errorf("missing [REDACTED:EMAIL]: %s", redacted)
	}

	if strings.Contains(redacted, "123-45-6789") {
		t.Errorf("SSN was not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED:SSN]") {
		t.Errorf("missing [REDACTED:SSN]: %s", redacted)
	}

	if strings.Contains(redacted, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS Key was not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED:AWS_KEY]") {
		t.Errorf("missing [REDACTED:AWS_KEY]: %s", redacted)
	}

	if strings.Contains(redacted, "sk-proj-1234567890abcdefghijklmn") {
		t.Errorf("OpenAI key was not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED:OPENAI_KEY]") {
		t.Errorf("missing [REDACTED:OPENAI_KEY]: %s", redacted)
	}
}

func TestRedactor_CreditCards_LuhnValidation(t *testing.T) {
	r := NewRedactor()

	// Valid test card: 4532015000000007 -> Luhn valid (sum=30)
	validCard := "Payment made with card 4532015000000007 for verification."
	redactedValid := r.RedactText(validCard)
	if strings.Contains(redactedValid, "4532015000000007") || !strings.Contains(redactedValid, "[REDACTED:CREDIT_CARD]") {
		t.Errorf("valid card was not redacted: %s", redactedValid)
	}

	// Invalid card number (fails Luhn mod-10)
	invalidCard := "Tracking code 4532015000000001 was scanned."
	redactedInvalid := r.RedactText(invalidCard)
	if strings.Contains(redactedInvalid, "[REDACTED:CREDIT_CARD]") {
		t.Errorf("non-card number was falsely redacted as credit card: %s", redactedInvalid)
	}
}
