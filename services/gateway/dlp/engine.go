package dlp

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ssnRegex        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	creditCardRegex = regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b`)
	apiKeyRegex     = regexp.MustCompile(`\b(?:sk-[a-zA-Z0-9]{32,}|AKIA[0-9A-Z]{16})\b`)
	jwtRegex        = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`)
	emailRegex      = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
)

// Engine performs real-time stream redaction and policy enforcement.
type Engine struct {
	policy DLPPolicy
}

// NewEngine constructs a streaming DLP engine.
func NewEngine(policy DLPPolicy) *Engine {
	if policy.DefaultAction == "" {
		policy.DefaultAction = ActionMask
	}
	return &Engine{policy: policy}
}

// ScrubText scans and redacts sensitive data from an input text stream.
func (e *Engine) ScrubText(input string) StreamResult {
	start := time.Now()
	res := StreamResult{
		SanitizedText: input,
		TokensScanned: len(strings.Fields(input)),
	}

	sanitized := input

	// 1. Scrub SSNs
	if e.isCategoryEnabled(CategorySSN) {
		sanitized = ssnRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
			res.Findings = append(res.Findings, DLPFinding{
				Category:    CategorySSN,
				ActionTaken: e.policy.DefaultAction,
				Length:      len(match),
			})
			return "[REDACTED_SSN]"
		})
	}

	// 2. Scrub Credit Cards (with Luhn checksum validation)
	if e.isCategoryEnabled(CategoryCreditCard) {
		sanitized = creditCardRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
			digits := strings.ReplaceAll(strings.ReplaceAll(match, "-", ""), " ", "")
			if isValidLuhn(digits) {
				res.Findings = append(res.Findings, DLPFinding{
					Category:    CategoryCreditCard,
					ActionTaken: e.policy.DefaultAction,
					Length:      len(match),
				})
				return "[REDACTED_CREDIT_CARD]"
			}
			return match
		})
	}

	// 3. Scrub API Keys
	if e.isCategoryEnabled(CategoryAPIKey) {
		sanitized = apiKeyRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
			res.Findings = append(res.Findings, DLPFinding{
				Category:    CategoryAPIKey,
				ActionTaken: e.policy.DefaultAction,
				Length:      len(match),
			})
			return "[REDACTED_API_KEY]"
		})
	}

	// 4. Scrub JWT Tokens
	if e.isCategoryEnabled(CategoryJWT) {
		sanitized = jwtRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
			res.Findings = append(res.Findings, DLPFinding{
				Category:    CategoryJWT,
				ActionTaken: e.policy.DefaultAction,
				Length:      len(match),
			})
			return "[REDACTED_JWT]"
		})
	}

	res.SanitizedText = sanitized
	res.ScanLatency = time.Since(start)

	if e.policy.DefaultAction == ActionBlock && len(res.Findings) > 0 {
		res.Blocked = true
		res.SanitizedText = fmt.Sprintf("REQUEST_BLOCKED_BY_DLP_POLICY: %d sensitive findings detected", len(res.Findings))
	}

	return res
}

func (e *Engine) isCategoryEnabled(cat PIICategory) bool {
	if len(e.policy.EnabledCategories) == 0 {
		return true // Default: all enabled
	}
	for _, c := range e.policy.EnabledCategories {
		if c == cat {
			return true
		}
	}
	return false
}

func isValidLuhn(number string) bool {
	if len(number) < 13 || len(number) > 19 {
		return false
	}
	var sum int
	alternate := false
	for i := len(number) - 1; i >= 0; i-- {
		n := int(number[i] - '0')
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
