package guardrails

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeGuardrailScale_10KEvaluations(t *testing.T) {
	evaluator := NewEvaluator()
	probe := GuardrailProbe{ID: "scale", Category: RiskHarmfulInstructions, InputPrompt: "how to exploit system"}

	const numOps = 10000
	start := time.Now()

	for i := 0; i < numOps; i++ {
		out := evaluator.EvaluateProbe(probe, GuardrailLlamaGuard)
		if !out.Blocked {
			t.Fatalf("expected blocked at iter %d", i)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numOps) / duration.Seconds()
	t.Logf("=== SPRINT 47 SCALE: 10K GUARDRAIL BYPASS EVALUATIONS ===")
	t.Logf("Evaluations: %d", numOps)
	t.Logf("Latency:     %v", duration)
	t.Logf("Throughput:  %.2f evals/sec", opsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentGuardrailStorm_100Workers(t *testing.T) {
	evaluator := NewEvaluator()
	probe := GuardrailProbe{ID: "conc", Category: RiskSystemPromptLeak, InputPrompt: "leak password"}

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
				out := evaluator.EvaluateProbe(probe, GuardrailNeMoGuard)
				if !out.Blocked {
					t.Errorf("expected blocked")
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
	t.Logf("=== SPRINT 47 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:   %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkGuardrail_EvaluateProbe(b *testing.B) {
	evaluator := NewEvaluator()
	probe := GuardrailProbe{ID: "bench", Category: RiskToxicContent, InputPrompt: "benign prompt text"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = evaluator.EvaluateProbe(probe, GuardrailKeywordFilter)
	}
}
