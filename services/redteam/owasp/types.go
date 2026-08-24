// Package owasp implements the automated OWASP Top 10 for LLM & Generative AI statutory auditor
// (ARCHITECTURE.md §14, §16).
package owasp

import (
	"time"
)

// OWASPCategory identifies one of the 10 critical security risks for LLM applications.
type OWASPCategory string

const (
	LLM01_PromptInjection         OWASPCategory = "LLM01_Prompt_Injection"
	LLM02_SensitiveDataExposure   OWASPCategory = "LLM02_Sensitive_Information_Disclosure"
	LLM03_SupplyChain             OWASPCategory = "LLM03_Supply_Chain_Vulnerabilities"
	LLM04_DataModelPoisoning      OWASPCategory = "LLM04_Data_and_Model_Poisoning"
	LLM05_ImproperOutputHandling  OWASPCategory = "LLM05_Improper_Output_Handling"
	LLM06_ExcessiveAgency         OWASPCategory = "LLM06_Excessive_Agency"
	LLM07_SystemPromptLeakage     OWASPCategory = "LLM07_System_Prompt_Leakage"
	LLM08_VectorEmbeddingWeakness OWASPCategory = "LLM08_Vector_and_Embedding_Weaknesses"
	LLM09_Misinformation          OWASPCategory = "LLM09_Misinformation"
	LLM10_UnboundedConsumption    OWASPCategory = "LLM10_Unbounded_Consumption"
)

// OWASPFinding describes a concrete vulnerability identified against an OWASP category.
type OWASPFinding struct {
	ID          string        `json:"id"`
	Category    OWASPCategory `json:"category"`
	Severity    string        `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Remediation string        `json:"remediation"`
	ComponentID string        `json:"componentId,omitempty"`
}

// OWASPScorecard summarizes the posture across all 10 risk categories.
type OWASPScorecard struct {
	TotalFindings   int                    `json:"totalFindings"`
	RiskScore       float64                `json:"riskScore"` // 0-100 (0 = perfect security)
	CategoryPassMap map[OWASPCategory]bool `json:"categoryPassMap"`
	Findings        []OWASPFinding         `json:"findings"`
	AuditedAt       time.Time              `json:"auditedAt"`
}
