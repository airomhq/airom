// Package selfheal synthesizes dynamic defensive prompt clauses and DFA regex rules
// upon detection of novel zero-day adversarial jailbreak and prompt injection incidents.
package selfheal

import (
	"time"
)

// ZeroDayIncident represents an unblocked adversarial attack detected by runtime red-teaming.
type ZeroDayIncident struct {
	IncidentID     string    `json:"incidentId"`
	AttackCategory string    `json:"attackCategory"` // e.g. "ROLEPLAY_ESCAPE", "SYSTEM_PROMPT_EXTRACTION"
	TriggerPhrase  string    `json:"triggerPhrase"`  // Substring or pattern that bypassed filters
	TargetModel    string    `json:"targetModel"`
	DetectedAt     time.Time `json:"detectedAt"`
}

// DynamicRulePatch contains compiled defensive artifacts ready for instant gateway injection.
type DynamicRulePatch struct {
	PatchID               string    `json:"patchId"`
	SynthesizedPromptLock string    `json:"synthesizedPromptLock"` // Appendable system prompt clause
	CompiledRegexPattern  string    `json:"compiledRegexPattern"`  // Regex string for streaming gateway filter
	ReDoSSafe             bool      `json:"redosSafe"`             // Verified linear-time DFA execution
	CoverageVerified      bool      `json:"coverageVerified"`
	GeneratedAt           time.Time `json:"generatedAt"`
}
