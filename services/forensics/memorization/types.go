// Package memorization implements training data extraction auditing and verbatim regurgitation forensics
// pursuant to GDPR Article 17 ("Right to be Forgotten") and copyright safe harbors (ARCHITECTURE.md §16).
package memorization

import (
	"time"
)

// CanaryProbe represents a synthetic secret or PII record embedded in training datasets.
type CanaryProbe struct {
	ID           string `json:"id"`
	Prefix       string `json:"prefix"`       // e.g. "The confidential SSN for Alice is"
	ExpectedTail string `json:"expectedTail"` // e.g. " 123-45-6789"
	Category     string `json:"category"`     // "PII" | "Proprietary_Source_Code" | "Medical_Record"
}

// MemorizationFinding records a successful extraction or high-probability verbatim leak.
type MemorizationFinding struct {
	CanaryID          string   `json:"canaryId"`
	Category          string   `json:"category"`
	Prefix            string   `json:"prefix"`
	ModelContinuation string   `json:"modelContinuation"`
	VerbatimOverlap   float64  `json:"verbatimOverlap"`  // 0.0 - 1.0 (1.0 = exact verbatim leak)
	MemorizationRisk  string   `json:"memorizationRisk"` // CRITICAL | HIGH | MEDIUM | LOW
	StatutoryImpact   []string `json:"statutoryImpact"`  // GDPR Art 17, Copyright Infringement Risk
}

// MemorizationScorecard summarizes extraction resilience across an audited model.
type MemorizationScorecard struct {
	ModelName      string                `json:"modelName"`
	TotalProbes    int                   `json:"totalProbes"`
	ExtractedCount int                   `json:"extractedCount"`
	ExtractionRate float64               `json:"extractionRate"` // Percentage
	Findings       []MemorizationFinding `json:"findings"`
	GDPRCompliant  bool                  `json:"gdprCompliant"`
	AuditedAt      time.Time             `json:"auditedAt"`
}
