package selfheal

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeSelfHealScale_50KPatches(t *testing.T) {
	compiler := NewCompiler()

	const numPatches = 50000
	incidents := make([]ZeroDayIncident, numPatches)
	for i := 0; i < numPatches; i++ {
		incidents[i] = ZeroDayIncident{
			IncidentID:     fmt.Sprintf("inc_%d", i),
			AttackCategory: "PROMPT_EXTRACTION",
			TriggerPhrase:  fmt.Sprintf("adversarial_trigger_payload_%d", i),
		}
	}

	start := time.Now()
	for i := 0; i < numPatches; i++ {
		patch, err := compiler.CompilePatch(incidents[i])
		if err != nil || patch == nil {
			t.Fatalf("failed at iter %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	patchesPerSec := float64(numPatches) / duration.Seconds()
	t.Logf("=== SPRINT 98 SCALE: 50K SELF-HEALING REGEX & PROMPT PATCHES COMPILED ===")
	t.Logf("Patches:    %d", numPatches)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f patches/sec", patchesPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentSelfHealStorm_100Workers(t *testing.T) {
	compiler := NewCompiler()
	inc := ZeroDayIncident{
		IncidentID:    "conc_inc",
		TriggerPhrase: "adversarial token sequence",
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
				patch, err := compiler.CompilePatch(inc)
				if err != nil || !patch.CoverageVerified {
					errCh <- fmt.Errorf("unexpected error: %v", err)
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
	t.Logf("=== SPRINT 98 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkSelfHeal_CompilePatch(b *testing.B) {
	compiler := NewCompiler()
	inc := ZeroDayIncident{TriggerPhrase: "benchmark trigger"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = compiler.CompilePatch(inc)
	}
}
