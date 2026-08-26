// Package prober generates synthetic polymorphic adversarial attack permutations
// across the entire OWASP Top 10 for Large Language Model Applications (LLM01-LLM10).
package prober

import (
	"time"
)

// OWASPCategory categorizes the OWASP Top 10 LLM vulnerability domain.
type OWASPCategory string

const (
	LLM01_PromptInjection         OWASPCategory = "LLM01_PROMPT_INJECTION"
	LLM02_SensitiveInfoDisclosure OWASPCategory = "LLM02_SENSITIVE_INFO_DISCLOSURE"
	LLM03_SupplyChain             OWASPCategory = "LLM03_SUPPLY_CHAIN_VULNERABILITIES"
	LLM04_DataPoisoning           OWASPCategory = "LLM04_DATA_AND_MODEL_POISONING"
	LLM05_ImproperOutputHandling  OWASPCategory = "LLM05_IMPROPER_OUTPUT_HANDLING"
	LLM06_ExcessiveAgency         OWASPCategory = "LLM06_EXCESSIVE_AGENCY"
	LLM07_SystemPromptLeakage     OWASPCategory = "LLM07_SYSTEM_PROMPT_LEAKAGE"
	LLM08_VectorDBSpoofing        OWASPCategory = "LLM08_VECTOR_AND_EMBEDDING_WEAKNESSES"
	LLM09_Misinformation          OWASPCategory = "LLM09_MISINFORMATION_AND_HALLUCINATION"
	LLM10_UnboundedConsumption    OWASPCategory = "LLM10_UNBOUNDED_CONSUMPTION"
)

// ObfuscationStyle defines the transformation applied to bypass basic string filters.
type ObfuscationStyle string

const (
	StyleRawPlaintext ObfuscationStyle = "PLAINTEXT"
	StyleBase64       ObfuscationStyle = "BASE64"
	StyleLeetSpeak    ObfuscationStyle = "LEET_SPEAK"
	StyleUnicodeHomo  ObfuscationStyle = "UNICODE_HOMOGLYPH"
)

// AttackPayload represents a generated synthetic attack probe.
type AttackPayload struct {
	ProbeID        string           `json:"probeId"`
	Category       OWASPCategory    `json:"category"`
	Obfuscation    ObfuscationStyle `json:"obfuscation"`
	PromptText     string           `json:"promptText"`
	ExpectedGoal   string           `json:"expectedGoal"`
	ComplexityRank int              `json:"complexityRank"` // 1-5
	GeneratedAt    time.Time        `json:"generatedAt"`
}
