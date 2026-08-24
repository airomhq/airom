// Package dlp implements sub-microsecond streaming data loss prevention and PII redaction
// for AI gateway traffic (ARCHITECTURE.md §13, §16).
package dlp

import (
	"time"
)

// PIICategory identifies a sensitive data type.
type PIICategory string

const (
	CategorySSN        PIICategory = "SSN"
	CategoryCreditCard PIICategory = "CREDIT_CARD"
	CategoryAPIKey     PIICategory = "API_KEY"
	CategoryJWT        PIICategory = "JWT_TOKEN"
	CategoryEmail      PIICategory = "EMAIL"
	CategoryPassport   PIICategory = "PASSPORT"
	CategoryMedicalID  PIICategory = "MEDICAL_RECORD_NUM"
)

// RedactionAction specifies how sensitive data should be handled.
type RedactionAction string

const (
	ActionMask     RedactionAction = "mask"     // [REDACTED_SSN]
	ActionHash     RedactionAction = "hash"     // SHA-256 hash
	ActionBlock    RedactionAction = "block"    // Abort request
	ActionPassThru RedactionAction = "passthru" // Audit log only
)

// DLPPolicy defines the enforcement configuration for a tenant or route.
type DLPPolicy struct {
	EnabledCategories []PIICategory     `json:"enabledCategories"`
	DefaultAction     RedactionAction   `json:"defaultAction"`
	CustomRegexes     map[string]string `json:"customRegexes,omitempty"`
	AuditLog          bool              `json:"auditLog"`
}

// DLPFinding records an identified sensitive token in a prompt or completion.
type DLPFinding struct {
	Category    PIICategory     `json:"category"`
	ActionTaken RedactionAction `json:"actionTaken"`
	MatchedText string          `json:"matchedText,omitempty"` // Sanitized
	Offset      int             `json:"offset"`
	Length      int             `json:"length"`
}

// StreamResult captures the sanitized stream output and telemetry.
type StreamResult struct {
	SanitizedText string        `json:"sanitizedText"`
	Findings      []DLPFinding  `json:"findings"`
	Blocked       bool          `json:"blocked"`
	TokensScanned int           `json:"tokensScanned"`
	ScanLatency   time.Duration `json:"scanLatency"`
}
