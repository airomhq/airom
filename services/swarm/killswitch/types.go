// Package killswitch implements a distributed, ultra-low latency kill-switch mesh
// for instant termination of runaway, compromised, or non-conformant multi-agent swarms.
package killswitch

import (
	"time"
)

// Scope defines the blast radius of the termination signal.
type Scope string

const (
	ScopeSingleAgent  Scope = "SINGLE_AGENT"
	ScopeAgentCluster Scope = "AGENT_CLUSTER"
	ScopeGlobalMesh   Scope = "GLOBAL_MESH"
)

// HaltReason details why the kill switch was triggered.
type HaltReason string

const (
	ReasonRunawayLoop        HaltReason = "RUNAWAY_RECURSIVE_LOOP"
	ReasonPromptInjection    HaltReason = "PROMPT_INJECTION_COMPROMISE"
	ReasonUnauthorizedSpend  HaltReason = "UNAUTHORIZED_FINANCIAL_SPEND"
	ReasonManualIntervention HaltReason = "HUMAN_EMERGENCY_STOP"
)

// KillSignal models an active halt directive.
type KillSignal struct {
	SignalID string     `json:"signalId"`
	Scope    Scope      `json:"scope"`
	TargetID string     `json:"targetId"` // Specific agent ID or cluster ID
	Reason   HaltReason `json:"reason"`
	IssuerID string     `json:"issuerId"`
	IssuedAt time.Time  `json:"issuedAt"`
}

// NodeStatus represents the operational status of an agent node in the mesh.
type NodeStatus struct {
	AgentID     string     `json:"agentId"`
	ClusterID   string     `json:"clusterId"`
	IsHalted    bool       `json:"isHalted"`
	HaltReason  HaltReason `json:"haltReason,omitempty"`
	LastCheckIn time.Time  `json:"lastCheckIn"`
}
