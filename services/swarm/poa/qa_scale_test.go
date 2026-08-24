package poa

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremePOAScale_50KActions(t *testing.T) {
	gate := NewGate()

	gate.RegisterGrant(POAGrant{
		AgentID:              "agent-scale",
		AuthorizedScopes:     []POAScope{ScopeFinancialPayment},
		PerTransactionMaxUSD: 10000.0,
		ValidUntil:           time.Now().UTC().Add(100 * time.Hour),
	})

	const numActions = 50000
	req := ActionRequest{
		RequestID: "scale",
		AgentID:   "agent-scale",
		Scope:     ScopeFinancialPayment,
		AmountUSD: 50.0,
	}

	start := time.Now()
	for i := 0; i < numActions; i++ {
		dec := gate.EvaluateAction(req)
		if !dec.Approved {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	actionsPerSec := float64(numActions) / duration.Seconds()
	t.Logf("=== SPRINT 66 SCALE: 50K AGENTIC POA DECISION EVALUATIONS ===")
	t.Logf("Actions:    %d", numActions)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f actions/sec", actionsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentPOAStorm_100Workers(t *testing.T) {
	gate := NewGate()
	const numWorkers = 100
	const iterations = 500

	for i := 0; i < numWorkers; i++ {
		gate.RegisterGrant(POAGrant{
			AgentID:              fmt.Sprintf("agent-%d", i),
			AuthorizedScopes:     []POAScope{ScopeFinancialPayment},
			PerTransactionMaxUSD: 1000.0,
		})
	}

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			req := ActionRequest{
				RequestID: fmt.Sprintf("req-%d", workerID),
				AgentID:   fmt.Sprintf("agent-%d", workerID),
				Scope:     ScopeFinancialPayment,
				AmountUSD: 10.0,
			}
			for j := 0; j < iterations; j++ {
				dec := gate.EvaluateAction(req)
				if !dec.Approved {
					errCh <- fmt.Errorf("worker %d iter %d rejected", workerID, j)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrency error: %v", err)
	}

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 66 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkPOA_EvaluateAction(b *testing.B) {
	gate := NewGate()
	gate.RegisterGrant(POAGrant{
		AgentID:          "bench",
		AuthorizedScopes: []POAScope{ScopeFinancialPayment},
	})
	req := ActionRequest{AgentID: "bench", Scope: ScopeFinancialPayment, AmountUSD: 10.0}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gate.EvaluateAction(req)
	}
}
