package bft

import (
	"testing"
)

func TestQA_AdversarialForgedProposalIDs(t *testing.T) {
	coord := NewCoordinator(4)

	prop := coord.ProposeAction("agent-1", "ACT", "pay")
	votes := []AgentVote{
		{VoterAgentID: "agent-1", ProposalID: "unrelated-prop-id", Approved: true},
		{VoterAgentID: "agent-2", ProposalID: "unrelated-prop-id", Approved: true},
	}

	verdict := coord.EvaluateVotes(prop.ProposalID, votes)
	if verdict.IsCommitted || verdict.AffirmativeVotes != 0 {
		t.Fatalf("expected 0 matching votes for forged proposal ID")
	}
}

func TestQA_AdversarialZeroVotes(t *testing.T) {
	coord := NewCoordinator(4)
	prop := coord.ProposeAction("agent-1", "ACT", "pay")

	verdict := coord.EvaluateVotes(prop.ProposalID, nil)
	if verdict.IsCommitted || verdict.AffirmativeVotes != 0 {
		t.Fatalf("expected uncommitted on zero votes")
	}
}
