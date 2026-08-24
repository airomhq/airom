package drift

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeDriftScale_50KComputations(t *testing.T) {
	detector := NewDetector()

	base := []float64{100, 200, 300, 400, 500, 400, 300, 200, 100, 50}
	act := []float64{120, 210, 290, 410, 480, 410, 310, 190, 110, 60}

	const numOps = 50000
	start := time.Now()

	for i := 0; i < numOps; i++ {
		res := detector.ComputePSI("feature", base, act)
		if res.Severity == "" {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numOps) / duration.Seconds()
	t.Logf("=== SPRINT 70 SCALE: 50K POPULATION STABILITY INDEX (PSI) DRIFT SCANS ===")
	t.Logf("Calculations: %d", numOps)
	t.Logf("Latency:      %v", duration)
	t.Logf("Throughput:   %.2f calcs/sec", opsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentDriftStorm_100Workers(t *testing.T) {
	detector := NewDetector()
	base := []float64{100, 200, 300}
	act := []float64{110, 190, 310}

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
				res := detector.ComputePSI("f", base, act)
				if res.Severity != DriftNegligible {
					t.Errorf("unexpected drift severity")
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
	t.Logf("=== SPRINT 70 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:    %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkDrift_ComputePSI(b *testing.B) {
	detector := NewDetector()
	base := []float64{100, 200, 300, 400, 500}
	act := []float64{110, 190, 310, 390, 510}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.ComputePSI("bench", base, act)
	}
}
