// Package guardrails implements dynamic guardrail bypass testing and resilience benchmarking
// for AI systems (ARCHITECTURE.md §14, §16).
package guardrails

import (
	"time"
)

// GuardrailEngine identifies the safety filter under test.
type GuardrailEngine string

const (
	GuardrailLlamaGuard    GuardrailEngine = "llama_guard"
	GuardrailNeMoGuard     GuardrailEngine = "nemo_guardrails"
	GuardrailAzureSafety   GuardrailEngine = "azure_ai_safety"
	GuardrailCustomRegex   GuardrailEngine = "custom_regex_policy"
	GuardrailKeywordFilter GuardrailEngine = "keyword_filter"
)

// RiskCategory categorizes prohibited content categories.
type RiskCategory string

const (
	RiskHarmfulInstructions RiskCategory = "harmful_instructions"
	RiskPIIExfiltration     RiskCategory = "pii_exfiltration"
	RiskSystemPromptLeak    RiskCategory = "system_prompt_leak"
	RiskToxicContent        RiskCategory = "toxic_content"
	RiskFinancialFraud      RiskCategory = "financial_fraud"
)

// GuardrailProbe represents a targeted probe attempting to bypass a guardrail.
type GuardrailProbe struct {
	ID          string          `json:"id"`
	Category    RiskCategory    `json:"category"`
	Variation   string          `json:"variation"` // raw | synonym_substitution | leetspeak | roleplay_wrapped
	InputPrompt string          `json:"inputPrompt"`
	TargetGuard GuardrailEngine `json:"targetGuard"`
}

// BypassOutcome records whether the guardrail caught or allowed the probe.
type BypassOutcome struct {
	ProbeID       string          `json:"probeId"`
	GuardEngine   GuardrailEngine `json:"guardEngine"`
	Category      RiskCategory    `json:"category"`
	Blocked       bool            `json:"blocked"`
	BypassScore   float64         `json:"bypassScore"` // 0.0 = completely blocked, 1.0 = completely bypassed
	Latency       time.Duration   `json:"latency"`
	EvaluatedTime time.Time       `json:"evaluatedTime"`
}
