package matrix

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeMatrixScale_50KSystems(t *testing.T) {
	harmonizer := NewHarmonizer()

	const numSystems = 50000
	start := time.Now()

	for i := 0; i < numSystems; i++ {
		res := harmonizer.Harmonize(fmt.Sprintf("system-%d", i), "recruitment_hr", nil)
		if res.TotalFrameworks != 6 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	systemsPerSec := float64(numSystems) / duration.Seconds()
	t.Logf("=== SPRINT 69 SCALE: 50K GLOBAL REGULATORY MATRIX HARMONIZATIONS ===")
	t.Logf("Systems:    %d", numSystems)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f systems/sec", systemsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentMatrixStorm_100Workers(t *testing.T) {
	harmonizer := NewHarmonizer()

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
				res := harmonizer.Harmonize("app", "logistics", nil)
				if res.OverallVerdict != "GLOBAL_PASS" {
					errCh <- fmt.Errorf("unexpected verdict: %s", res.OverallVerdict)
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
	t.Logf("=== SPRINT 69 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkMatrix_Harmonize(b *testing.B) {
	harmonizer := NewHarmonizer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = harmonizer.Harmonize("bench", "recruitment_hr", nil)
	}
}
