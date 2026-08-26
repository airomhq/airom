package logic

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeLogicScale_50KPlans(t *testing.T) {
	verifier := NewVerifier()

	const numPlans = 50000
	plans := make([]AgentActionPlan, numPlans)
	for i := 0; i < numPlans; i++ {
		plans[i] = AgentActionPlan{
			PlanID:        fmt.Sprintf("plan_%d", i),
			ActionVerb:    "FETCH_METRICS",
			EstimatedCost: 1.0,
			IsAuthSigned:  true,
		}
	}

	start := time.Now()
	for i := 0; i < numPlans; i++ {
		res := verifier.ProvePlan(plans[i])
		if !res.AxiomHolds {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	plansPerSec := float64(numPlans) / duration.Seconds()
	t.Logf("=== SPRINT 101 SCALE: 50K AGENT ACTION PLANS FORMALLY PROVEN ===")
	t.Logf("Plans:      %d", numPlans)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f plans/sec", plansPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentLogicStorm_100Workers(t *testing.T) {
	verifier := NewVerifier()
	plan := AgentActionPlan{
		PlanID:        "conc_plan",
		ActionVerb:    "QUERY_DATA",
		EstimatedCost: 0.5,
		IsAuthSigned:  true,
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
				res := verifier.ProvePlan(plan)
				if !res.AxiomHolds {
					errCh <- fmt.Errorf("unexpected failure")
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
	t.Logf("=== SPRINT 101 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkLogic_ProvePlan(b *testing.B) {
	verifier := NewVerifier()
	plan := AgentActionPlan{
		PlanID:        "bench_plan",
		ActionVerb:    "QUERY_DATA",
		EstimatedCost: 0.5,
		IsAuthSigned:  true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.ProvePlan(plan)
	}
}
