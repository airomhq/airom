package circuit

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeCircuitScale_50KDelegations(t *testing.T) {
	ceilings := SafetyCeilings{MaxHopDepth: 100000, MaxTotalMessages: 100000}
	breaker := NewBreaker(ceilings)

	const numOps = 50000
	call := DelegationCall{CurrentHop: 1, DriftScore: 0.10, CostDelta: 0.0001}

	start := time.Now()
	for i := 0; i < numOps; i++ {
		err := breaker.AllowDelegation(call)
		if err != nil {
			t.Fatalf("failed at iter %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numOps) / duration.Seconds()
	t.Logf("=== SPRINT 65 SCALE: 50K SWARM CIRCUIT DELEGATION CHECKS ===")
	t.Logf("Operations: %d", numOps)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f ops/sec", opsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentCircuitStorm_100Workers(t *testing.T) {
	ceilings := SafetyCeilings{MaxHopDepth: 100000, MaxTotalMessages: 100000}
	breaker := NewBreaker(ceilings)

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			call := DelegationCall{CurrentHop: 1, DriftScore: 0.05}
			for j := 0; j < iterations; j++ {
				if err := breaker.AllowDelegation(call); err != nil {
					errCh <- err
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
	t.Logf("=== SPRINT 65 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkCircuit_AllowDelegation(b *testing.B) {
	ceilings := SafetyCeilings{MaxHopDepth: 10000000, MaxTotalMessages: 10000000}
	breaker := NewBreaker(ceilings)
	call := DelegationCall{CurrentHop: 1, DriftScore: 0.10}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = breaker.AllowDelegation(call)
	}
}
