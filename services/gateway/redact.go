package gateway

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	ssnRegex            = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	awsKeyRegex         = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	openAIKeyRegex      = regexp.MustCompile(`\bsk-[a-zA-Z0-9_-]{20,}\b`)
	anthropicKeyRegex   = regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9_-]{20,}\b`)
	jwtRegex            = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`)
	emailRegex          = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	creditCardCandidate = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
)

// Redactor performs fast in-flight PII and secret detection and sanitization.
type Redactor struct {
	maskEmails  bool
	maskSSNs    bool
	maskCards   bool
	maskSecrets bool
}

// NewRedactor initializes a configured PII and secret redactor.
func NewRedactor() *Redactor {
	return &Redactor{
		maskEmails:  true,
		maskSSNs:    true,
		maskCards:   true,
		maskSecrets: true,
	}
}

// RedactText scans and replaces sensitive entities in text with [REDACTED:<TYPE>].
func (r *Redactor) RedactText(input string) string {
	if input == "" {
		return ""
	}

	result := input

	// 1. Secrets & API Keys
	if r.maskSecrets {
		result = awsKeyRegex.ReplaceAllString(result, "[REDACTED:AWS_KEY]")
		result = anthropicKeyRegex.ReplaceAllString(result, "[REDACTED:ANTHROPIC_KEY]")
		result = openAIKeyRegex.ReplaceAllString(result, "[REDACTED:OPENAI_KEY]")
		result = jwtRegex.ReplaceAllString(result, "[REDACTED:JWT_TOKEN]")
	}

	// 2. SSN
	if r.maskSSNs {
		result = ssnRegex.ReplaceAllString(result, "[REDACTED:SSN]")
	}

	// 3. Credit Cards (Luhn Algorithm Verified)
	if r.maskCards {
		result = creditCardCandidate.ReplaceAllStringFunc(result, func(candidate string) string {
			digits := extractDigits(candidate)
			if len(digits) >= 13 && len(digits) <= 19 && isValidLuhn(digits) {
				return "[REDACTED:CREDIT_CARD]"
			}
			return candidate
		})
	}

	// 4. Email Addresses
	if r.maskEmails {
		result = emailRegex.ReplaceAllString(result, "[REDACTED:EMAIL]")
	}

	return result
}

func extractDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isValidLuhn implements the standard Luhn (mod-10) checksum validation for credit cards.
func isValidLuhn(digits string) bool {
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alternate := false

	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if n < 0 || n > 9 {
			return false
		}

		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}

		sum += n
		alternate = !alternate
	}

	return sum%10 == 0
}
