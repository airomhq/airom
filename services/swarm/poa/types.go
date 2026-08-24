// Package poa implements cryptographic Power-of-Attorney (POA) authority bounds and financial gates
// for autonomous AI agents (ARCHITECTURE.md §16).
package poa

import (
	"time"
)

// POAScope categorizes the legally binding domain an agent is authorized to act within.
type POAScope string

const (
	ScopeFinancialPayment POAScope = "financial_payment_execution"
	ScopeLegalContract    POAScope = "legal_contract_agreement"
	ScopeInfraWrite       POAScope = "production_infrastructure_write"
	ScopeCustomerCommit   POAScope = "customer_sla_commitment"
)

// POAGrant represents a cryptographically delegated authorization granted to an agent.
type POAGrant struct {
	AgentID              string     `json:"agentId"`
	PrincipalOrg         string     `json:"principalOrg"`
	AuthorizedScopes     []POAScope `json:"authorizedScopes"`
	PerTransactionMaxUSD float64    `json:"perTransactionMaxUsd"`
	DualCustodyThreshold float64    `json:"dualCustodyThresholdUsd"` // Requires human co-signer above this
	ValidUntil           time.Time  `json:"validUntil"`
}

// ActionRequest represents an intended external commitment by an agent.
type ActionRequest struct {
	RequestID     string    `json:"requestId"`
	AgentID       string    `json:"agentId"`
	Scope         POAScope  `json:"scope"`
	AmountUSD     float64   `json:"amountUsd,omitempty"`
	Description   string    `json:"description"`
	HumanCoSigner string    `json:"humanCoSigner,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// POADecision records whether the action is approved, rejected, or queued for dual custody.
type POADecision struct {
	RequestID        string    `json:"requestId"`
	Approved         bool      `json:"approved"`
	RequiresCoSigner bool      `json:"requiresCoSigner"`
	Reason           string    `json:"reason"`
	EvaluatedAt      time.Time `json:"evaluatedAt"`
}
