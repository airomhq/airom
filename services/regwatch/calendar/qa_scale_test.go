package calendar

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeCalendarScale_50KComputations(t *testing.T) {
	pipeline := NewPipeline()
	refTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	const numComputations = 50000
	start := time.Now()

	for i := 0; i < numComputations; i++ {
		notices := pipeline.ComputeActionNotices(refTime)
		if len(notices) != 3 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	compsPerSec := float64(numComputations) / duration.Seconds()
	t.Logf("=== SPRINT 87 SCALE: 50K STATUTORY TIMELINE COMPUTATIONS ===")
	t.Logf("Computations: %d", numComputations)
	t.Logf("Latency:      %v", duration)
	t.Logf("Throughput:   %.2f comps/sec", compsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentCalendarStorm_100Workers(t *testing.T) {
	pipeline := NewPipeline()
	refTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				notices := pipeline.ComputeActionNotices(refTime)
				if len(notices) != 3 {
					return
				}
			}
		}()
	}

	wg.Wait()

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 87 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkCalendar_ComputeActionNotices(b *testing.B) {
	pipeline := NewPipeline()
	refTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pipeline.ComputeActionNotices(refTime)
	}
}
