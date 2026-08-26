package bft

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeBFTScale_50KRounds(t *testing.T) {
	coord := NewCoordinator(7) // f=2, quorum = 5

	const numRounds = 50000
	start := time.Now()

	for i := 0; i < numRounds; i++ {
		prop := coord.ProposeAction("agent-1", "ACTION", "payload")
		votes := []AgentVote{
			{VoterAgentID: "agent-1", ProposalID: prop.ProposalID, Approved: true},
			{VoterAgentID: "agent-2", ProposalID: prop.ProposalID, Approved: true},
			{VoterAgentID: "agent-3", ProposalID: prop.ProposalID, Approved: true},
			{VoterAgentID: "agent-4", ProposalID: prop.ProposalID, Approved: true},
			{VoterAgentID: "agent-5", ProposalID: prop.ProposalID, Approved: true},
			{VoterAgentID: "agent-6", ProposalID: prop.ProposalID, Approved: false},
			{VoterAgentID: "agent-7", ProposalID: prop.ProposalID, Approved: false},
		}

		verdict := coord.EvaluateVotes(prop.ProposalID, votes)
		if !verdict.IsCommitted {
			t.Fatalf("failed consensus at iter %d", i)
		}
	}
	duration := time.Since(start)

	roundsPerSec := float64(numRounds) / duration.Seconds()
	t.Logf("=== SPRINT 100 SCALE: 50K MULTI-AGENT PBFT CONSENSUS ROUNDS EVALUATED ===")
	t.Logf("Rounds:     %d", numRounds)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f rounds/sec", roundsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentBFTStorm_100Workers(t *testing.T) {
	coord := NewCoordinator(4)

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				prop := coord.ProposeAction(fmt.Sprintf("w_%d", workerID), "ACTION", "data")
				votes := []AgentVote{
					{VoterAgentID: "a1", ProposalID: prop.ProposalID, Approved: true},
					{VoterAgentID: "a2", ProposalID: prop.ProposalID, Approved: true},
					{VoterAgentID: "a3", ProposalID: prop.ProposalID, Approved: true},
				}
				_ = coord.EvaluateVotes(prop.ProposalID, votes)
			}
		}(i)
	}

	wg.Wait()

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 100 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d consensus ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkBFT_EvaluateVotes(b *testing.B) {
	coord := NewCoordinator(4)
	prop := coord.ProposeAction("agent-1", "ACT", "pay")
	votes := []AgentVote{
		{VoterAgentID: "a1", ProposalID: prop.ProposalID, Approved: true},
		{VoterAgentID: "a2", ProposalID: prop.ProposalID, Approved: true},
		{VoterAgentID: "a3", ProposalID: prop.ProposalID, Approved: true},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = coord.EvaluateVotes(prop.ProposalID, votes)
	}
}
