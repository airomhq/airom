package fairness

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeFairnessScale_50KScorecards(t *testing.T) {
	engine := NewTelemetryEngine()

	groups := []GroupStatistics{
		{GroupLabel: "Group_A", TotalApplied: 1000, TotalSelected: 500},
		{GroupLabel: "Group_B", TotalApplied: 1000, TotalSelected: 480},
		{GroupLabel: "Group_C", TotalApplied: 1000, TotalSelected: 450},
		{GroupLabel: "Group_D", TotalApplied: 1000, TotalSelected: 420},
	}

	const numOps = 50000
	start := time.Now()

	for i := 0; i < numOps; i++ {
		sc := engine.EvaluateFairness("app", groups)
		if sc.OverallFairness != "FAIR_COMPLIANT" {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numOps) / duration.Seconds()
	t.Logf("=== SPRINT 72 SCALE: 50K CONTINUOUS DEMOGRAPHIC PARITY FAIRNESS AUDITS ===")
	t.Logf("Audits:     %d", numOps)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f audits/sec", opsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentFairnessStorm_100Workers(t *testing.T) {
	engine := NewTelemetryEngine()
	groups := []GroupStatistics{
		{GroupLabel: "Cohort_1", TotalApplied: 500, TotalSelected: 250},
		{GroupLabel: "Cohort_2", TotalApplied: 500, TotalSelected: 220},
	}

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sc := engine.EvaluateFairness("app", groups)
				if sc.OverallFairness != "FAIR_COMPLIANT" {
					t.Errorf("unexpected failure")
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
	t.Logf("=== SPRINT 72 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkFairness_EvaluateFairness(b *testing.B) {
	engine := NewTelemetryEngine()
	groups := []GroupStatistics{
		{GroupLabel: "G1", TotalApplied: 100, TotalSelected: 50},
		{GroupLabel: "G2", TotalApplied: 100, TotalSelected: 45},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.EvaluateFairness("bench", groups)
	}
}
