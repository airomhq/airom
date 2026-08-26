package bft

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Coordinator manages PBFT consensus rounds across registered autonomous agents.
type Coordinator struct {
	mu          sync.RWMutex
	totalAgents int
	fFaults     int
	quorumReq   int
}

// NewCoordinator constructs a new PBFT swarm coordinator. Total agents N >= 3f + 1.
func NewCoordinator(totalAgents int) *Coordinator {
	if totalAgents < 4 {
		totalAgents = 4 // Default minimal Byzantine tolerant cluster (f=1, N=4)
	}
	f := (totalAgents - 1) / 3
	quorum := 2*f + 1

	return &Coordinator{
		totalAgents: totalAgents,
		fFaults:     f,
		quorumReq:   quorum,
	}
}

// ProposeAction initiates a pre-prepare consensus round.
func (c *Coordinator) ProposeAction(primaryAgentID, actionType, payload string) *AgentProposal {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", primaryAgentID, actionType, payload, now.Format(time.RFC3339Nano))))
	digest := hex.EncodeToString(h[:])
	propID := fmt.Sprintf("bft-prop-%s", digest[:8])

	return &AgentProposal{
		ProposalID:     propID,
		PrimaryAgentID: primaryAgentID,
		ActionType:     actionType,
		ActionPayload:  payload,
		ProposalDigest: digest,
		Timestamp:      now,
	}
}

// EvaluateVotes aggregates signed votes and computes whether quorum (2f+1) is achieved.
func (c *Coordinator) EvaluateVotes(proposalID string, votes []AgentVote) ConsensusVerdict {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now().UTC()
	affirmative := 0
	uniqueVoters := make(map[string]bool)

	for _, v := range votes {
		if v.ProposalID != proposalID {
			continue
		}
		// Prevent double-voting by same agent node
		if uniqueVoters[v.VoterAgentID] {
			continue
		}
		uniqueVoters[v.VoterAgentID] = true

		if v.Approved {
			affirmative++
		}
	}

	isCommitted := affirmative >= c.quorumReq
	phase := PhaseAborted
	if isCommitted {
		phase = PhaseFinalized
	}

	return ConsensusVerdict{
		ProposalID:       proposalID,
		IsCommitted:      isCommitted,
		TotalVoters:      len(uniqueVoters),
		AffirmativeVotes: affirmative,
		QuorumThreshold:  c.quorumReq,
		Phase:            phase,
		FinalizedAt:      now,
	}
}
