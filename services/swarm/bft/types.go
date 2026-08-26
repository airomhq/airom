// Package bft provides decentralized Practical Byzantine Fault Tolerant (PBFT) consensus
// for multi-agent autonomous swarms executing high-stakes tools and irreversible mutations.
package bft

import (
	"time"
)

// Phase represents the PBFT three-phase consensus lifecycle.
type Phase string

const (
	PhasePrePrepare Phase = "PRE_PREPARE"
	PhasePrepare    Phase = "PREPARE"
	PhaseCommit     Phase = "COMMIT"
	PhaseFinalized  Phase = "FINALIZED"
	PhaseAborted    Phase = "ABORTED"
)

// AgentProposal represents an action requested by a primary agent node.
type AgentProposal struct {
	ProposalID     string    `json:"proposalId"`
	PrimaryAgentID string    `json:"primaryAgentId"`
	ActionType     string    `json:"actionType"` // e.g. "WIRE_TRANSFER", "DEPLOY_MODEL", "ACTUATOR_MOVE"
	ActionPayload  string    `json:"actionPayload"`
	ProposalDigest string    `json:"proposalDigest"`
	Timestamp      time.Time `json:"timestamp"`
}

// AgentVote models an individual agent's validation and signed vote.
type AgentVote struct {
	VoterAgentID string    `json:"voterAgentId"`
	ProposalID   string    `json:"proposalId"`
	Phase        Phase     `json:"phase"`
	Approved     bool      `json:"approved"`
	VotedAt      time.Time `json:"votedAt"`
}

// ConsensusVerdict represents the PBFT quorum decision.
type ConsensusVerdict struct {
	ProposalID       string    `json:"proposalId"`
	IsCommitted      bool      `json:"isCommitted"`
	TotalVoters      int       `json:"totalVoters"`
	AffirmativeVotes int       `json:"affirmativeVotes"`
	QuorumThreshold  int       `json:"quorumThreshold"` // 2f + 1
	Phase            Phase     `json:"phase"`
	FinalizedAt      time.Time `json:"finalizedAt"`
}
