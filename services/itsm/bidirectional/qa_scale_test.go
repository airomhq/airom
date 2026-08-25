package bidirectional

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeITSMScale_50KTransitions(t *testing.T) {
	coordinator := NewCoordinator()

	const numTransitions = 50000
	start := time.Now()

	for i := 0; i < numTransitions; i++ {
		repoID := fmt.Sprintf("repo-%d", i)
		controlID := "CTRL-AI-01"

		// 1. Open
		_ = coordinator.OnGapDetected(PlatformJira, repoID, controlID, "HIGH", "Gap")

		// 2. Resolve
		_, _ = coordinator.OnGapResolved(repoID, controlID)
	}
	duration := time.Since(start)

	totalOps := numTransitions * 2
	opsPerSec := float64(totalOps) / duration.Seconds()
	t.Logf("=== SPRINT 79 SCALE: 50K ITSM INCIDENT STATE TRANSITIONS ===")
	t.Logf("Operations: %d", totalOps)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f ops/sec", opsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentITSMStorm_100Workers(t *testing.T) {
	coordinator := NewCoordinator()

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
				repoID := fmt.Sprintf("worker-%d-repo-%d", workerID, j)
				controlID := "EU-AI-ACT-10"

				tk := coordinator.OnGapDetected(PlatformJira, repoID, controlID, "HIGH", "Gap")
				if tk == nil {
					errCh <- fmt.Errorf("failed to open ticket")
					return
				}

				_, ok := coordinator.OnGapResolved(repoID, controlID)
				if !ok {
					errCh <- fmt.Errorf("failed to auto-resolve ticket")
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

	totalOps := numWorkers * iterations * 2
	duration := time.Since(start)
	t.Logf("=== SPRINT 79 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkITSM_LifecycleTransitions(b *testing.B) {
	coordinator := NewCoordinator()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = coordinator.OnGapDetected(PlatformJira, "repo-bench", "CTRL-1", "HIGH", "Summary")
		_, _ = coordinator.OnGapResolved("repo-bench", "CTRL-1")
	}
}
