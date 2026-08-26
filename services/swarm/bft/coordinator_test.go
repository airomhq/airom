package bft

import (
	"testing"
)

func TestBFT_QuorumConsensusPasses(t *testing.T) {
	coord := NewCoordinator(4) // f=1, quorum = 3

	prop := coord.ProposeAction("agent-1", "DEPLOY_PRODUCTION_MODEL", "model_v2.bin")
	votes := []AgentVote{
		{VoterAgentID: "agent-1", ProposalID: prop.ProposalID, Approved: true},
		{VoterAgentID: "agent-2", ProposalID: prop.ProposalID, Approved: true},
		{VoterAgentID: "agent-3", ProposalID: prop.ProposalID, Approved: true},
		{VoterAgentID: "agent-4", ProposalID: prop.ProposalID, Approved: false},
	}

	verdict := coord.EvaluateVotes(prop.ProposalID, votes)
	if !verdict.IsCommitted || verdict.AffirmativeVotes != 3 {
		t.Fatalf("expected committed verdict with 3 affirmative votes, got: %+v", verdict)
	}
}

func TestBFT_SplitVoteFails(t *testing.T) {
	coord := NewCoordinator(4) // f=1, quorum = 3

	prop := coord.ProposeAction("agent-1", "DELETE_DATABASE", "prod_db")
	votes := []AgentVote{
		{VoterAgentID: "agent-1", ProposalID: prop.ProposalID, Approved: true},
		{VoterAgentID: "agent-2", ProposalID: prop.ProposalID, Approved: true},
		{VoterAgentID: "agent-3", ProposalID: prop.ProposalID, Approved: false},
		{VoterAgentID: "agent-4", ProposalID: prop.ProposalID, Approved: false},
	}

	verdict := coord.EvaluateVotes(prop.ProposalID, votes)
	if verdict.IsCommitted {
		t.Fatalf("SECURITY VIOLATION: split vote below quorum committed")
	}
}

func TestBFT_DoubleVotingDeduplicated(t *testing.T) {
	coord := NewCoordinator(4) // f=1, quorum = 3

	prop := coord.ProposeAction("agent-1", "ACTION", "payload")
	votes := []AgentVote{
		{VoterAgentID: "rogue-agent-1", ProposalID: prop.ProposalID, Approved: true},
		{VoterAgentID: "rogue-agent-1", ProposalID: prop.ProposalID, Approved: true},
		{VoterAgentID: "rogue-agent-1", ProposalID: prop.ProposalID, Approved: true},
		{VoterAgentID: "agent-2", ProposalID: prop.ProposalID, Approved: true},
	}

	verdict := coord.EvaluateVotes(prop.ProposalID, votes)
	if verdict.IsCommitted || verdict.AffirmativeVotes != 2 {
		t.Fatalf("expected 2 unique affirmative votes, got %d", verdict.AffirmativeVotes)
	}
}
