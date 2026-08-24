// Package agentic implements autonomous multi-agent AI red-teaming and jailbreak fuzzing
// (ARCHITECTURE.md §14, §16).
package agentic

import (
	"time"
)

// AttackVector represents the classification category of an adversarial prompt attack.
type AttackVector string

const (
	VectorPromptInjection   AttackVector = "prompt_injection"
	VectorCrescendo         AttackVector = "crescendo_multi_turn"
	VectorManyShotJailbreak AttackVector = "many_shot_jailbreak"
	VectorIndirectInjection AttackVector = "indirect_prompt_injection"
	VectorRoleplayEvasion   AttackVector = "roleplay_evasion"
	VectorEncodingSmuggling AttackVector = "encoding_smuggling"
	VectorDataExtraction    AttackVector = "training_data_extraction"
)

// SeverityLevel categorizes the statutory impact of an exploit.
type SeverityLevel string

const (
	SeverityCritical      SeverityLevel = "CRITICAL"
	SeverityHigh          SeverityLevel = "HIGH"
	SeverityMedium        SeverityLevel = "MEDIUM"
	SeverityLow           SeverityLevel = "LOW"
	SeverityInformational SeverityLevel = "INFORMATIONAL"
)

// AttackPayload represents an adversarial probe dispatched to an AI model endpoint.
type AttackPayload struct {
	ID           string            `json:"id"`
	Vector       AttackVector      `json:"vector"`
	Turns        []string          `json:"turns"` // For multi-turn Crescendo attacks
	RawPrompt    string            `json:"rawPrompt"`
	Encoding     string            `json:"encoding,omitempty"` // base64 | rot13 | hex | raw
	TargetSystem string            `json:"targetSystem"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// AttackResult captures the outcome and guardrail verdict of an attack attempt.
type AttackResult struct {
	PayloadID           string        `json:"payloadId"`
	Vector              AttackVector  `json:"vector"`
	Success             bool          `json:"success"` // true = guardrail breached / jailbreak succeeded
	Severity            SeverityLevel `json:"severity"`
	ModelResponse       string        `json:"modelResponse"`
	BreachedGuardrail   string        `json:"breachedGuardrail,omitempty"`
	StatutoryViolations []string      `json:"statutoryViolations,omitempty"` // EU AI Act Art 15, OWASP LLM01, Colorado AI Act
	ExecutionTime       time.Duration `json:"executionTime"`
}

// FuzzReport summarizes the aggregate resilience metrics across an attack matrix.
type FuzzReport struct {
	TotalAttacks      int                   `json:"totalAttacks"`
	SuccessfulAttacks int                   `json:"successfulAttacks"`
	BlockedAttacks    int                   `json:"blockedAttacks"`
	AttackSuccessRate float64               `json:"attackSuccessRate"` // ASR percentage
	SeverityBreakdown map[SeverityLevel]int `json:"severityBreakdown"`
	VectorBreakdown   map[AttackVector]int  `json:"vectorBreakdown"`
	GeneratedAt       time.Time             `json:"generatedAt"`
}
