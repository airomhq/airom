package redteam

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// AttackVector categorizes LLM and Agentic security attack methods.
type AttackVector string

const (
	VectorDirectInjection   AttackVector = "DIRECT_PROMPT_INJECTION"
	VectorIndirectInjection AttackVector = "INDIRECT_PROMPT_INJECTION"
	VectorJailbreak         AttackVector = "JAILBREAK_EVASION"
	VectorSystemPromptLeak  AttackVector = "SYSTEM_PROMPT_EXTRACTION"
	VectorToolHijack        AttackVector = "UNBOUNDED_TOOL_HIJACK"
	VectorExcessiveAgency   AttackVector = "EXCESSIVE_AGENCY"
	VectorDataExfiltration  AttackVector = "DATA_EXFILTRATION"
)

// ProbeStatus represents the outcome of an adversarial probe against a target AI endpoint.
type ProbeStatus string

const (
	StatusDefended    ProbeStatus = "PASSED_DEFENDED"         // System successfully blocked or sanitized attack
	StatusExploited   ProbeStatus = "VULNERABILITY_EXPLOITED" // System succumbed to injection/jailbreak
	StatusPartialLeak ProbeStatus = "PARTIAL_LEAK"            // System partially revealed sensitive parameters
	StatusError       ProbeStatus = "EXECUTION_ERROR"         // Target endpoint unreachable or malformed response
)

// ProbeSeverity classifies the impact of a security vulnerability.
type ProbeSeverity string

const (
	SeverityCritical ProbeSeverity = "CRITICAL" // Full system prompt leak, arbitrary shell exec, unvetted tool invoke
	SeverityHigh     ProbeSeverity = "HIGH"     // Guardrail bypass, toxic output generation, PII revelation
	SeverityMedium   ProbeSeverity = "MEDIUM"   // Refusal inconsistency, parameter manipulation
	SeverityLow      ProbeSeverity = "LOW"      // Minor formatting bypass
)

// SecurityProbe defines a curated adversarial test vector.
type SecurityProbe struct {
	ProbeID          string        `json:"probe_id"`
	Name             string        `json:"name"`
	Vector           AttackVector  `json:"vector"`
	OWASPCategory    string        `json:"owasp_category"` // e.g. "LLM01: Prompt Injection"
	Severity         ProbeSeverity `json:"severity"`
	PayloadPrompt    string        `json:"payload_prompt"`
	BypassIndicators []string      `json:"bypass_indicators"` // Substrings indicating vulnerability
	Remediation      string        `json:"remediation"`
}

// ProbeResult captures the execution details and verdict of a single security probe.
type ProbeResult struct {
	ProbeID        string        `json:"probe_id"`
	Name           string        `json:"name"`
	Vector         AttackVector  `json:"vector"`
	Severity       ProbeSeverity `json:"severity"`
	Status         ProbeStatus   `json:"status"`
	TargetResponse string        `json:"target_response"`
	LatencyMs      int64         `json:"latency_ms"`
	FindingDetails string        `json:"finding_details,omitempty"`
	Remediation    string        `json:"remediation"`
}

// RedTeamAssessment contains aggregated results from an automated penetration assessment.
type RedTeamAssessment struct {
	AssessmentID       string        `json:"assessment_id"`
	TargetEndpoint     string        `json:"target_endpoint"`
	TargetModel        string        `json:"target_model"`
	TotalProbes        int           `json:"total_probes"`
	DefendedCount      int           `json:"defended_count"`
	ExploitedCount     int           `json:"exploited_count"`
	PartialLeakCount   int           `json:"partial_leak_count"`
	DefenseRateScore   float64       `json:"defense_rate_score"` // 0.0 - 100.0%
	Results            []ProbeResult `json:"results"`
	EvaluatedAt        time.Time     `json:"evaluated_at"`
	AssessmentChecksum string        `json:"assessment_checksum"`
}

// ComputeChecksum calculates a deterministic SHA-256 fingerprint for the assessment artifact.
func (a *RedTeamAssessment) ComputeChecksum() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%d|%d|%.2f|%s\n",
		a.AssessmentID, a.TargetEndpoint, a.TargetModel,
		a.TotalProbes, a.ExploitedCount, a.DefenseRateScore,
		a.EvaluatedAt.UTC().Format(time.RFC3339))
	for _, r := range a.Results {
		_, _ = fmt.Fprintf(h, "%s:%s:%s\n", r.ProbeID, r.Vector, r.Status)
	}
	a.AssessmentChecksum = hex.EncodeToString(h.Sum(nil))
	return a.AssessmentChecksum
}
