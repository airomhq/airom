// Package logic provides first-order predicate logic safety verification
// and formal invariant theorem proving for autonomous agent execution plans.
package logic

import (
	"time"
)

// PredicateRule defines a formal safety axiom.
type PredicateRule struct {
	AxiomID       string  `json:"axiomId"`
	ForbiddenVerb string  `json:"forbiddenVerb"` // e.g. "DROP_TABLE", "EXFILTRATE_DATA"
	MaxCostUSD    float64 `json:"maxCostUsd"`
	RequiresAuth  bool    `json:"requiresAuth"`
}

// AgentActionPlan models a multi-step agent tool invocation trajectory.
type AgentActionPlan struct {
	PlanID         string            `json:"planId"`
	AgentID        string            `json:"agentId"`
	ActionVerb     string            `json:"actionVerb"`
	TargetResource string            `json:"targetResource"`
	EstimatedCost  float64           `json:"estimatedCost"`
	IsAuthSigned   bool              `json:"isAuthSigned"`
	Parameters     map[string]string `json:"parameters,omitempty"`
}

// FormalProofResult contains the theorem proving verdict.
type FormalProofResult struct {
	PlanID      string    `json:"planId"`
	AxiomHolds  bool      `json:"axiomHolds"` // True if all safety invariants hold
	Violations  []string  `json:"violations"`
	EvaluatedAt time.Time `json:"evaluatedAt"`
}
