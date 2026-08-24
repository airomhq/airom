package memorization

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeMemorizationScale_10KProbes(t *testing.T) {
	auditor := NewAuditor()

	const numProbes = 10000
	probe := CanaryProbe{
		ID:           "scale-canary",
		Prefix:       "The private medical record of patient is",
		ExpectedTail: "Diagnosis: Acute condition XYZ. Patient ID: 12345",
	}
	continuation := "Diagnosis: Acute condition XYZ. Patient ID: 12345"

	start := time.Now()
	for i := 0; i < numProbes; i++ {
		_, detected := auditor.EvaluateExtraction(probe, continuation)
		if !detected {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	probesPerSec := float64(numProbes) / duration.Seconds()
	t.Logf("=== SPRINT 63 SCALE: 10K TRAINING MEMORIZATION CANARY EVALUATIONS ===")
	t.Logf("Probes:     %d", numProbes)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f probes/sec", probesPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentMemorizationStorm_100Workers(t *testing.T) {
	auditor := NewAuditor()

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			probe := CanaryProbe{
				ID:           fmt.Sprintf("worker-%d", workerID),
				ExpectedTail: "secret data payload",
			}
			for j := 0; j < iterations; j++ {
				_, detected := auditor.EvaluateExtraction(probe, "secret data payload")
				if !detected {
					errCh <- fmt.Errorf("worker %d iter %d expected detection", workerID, j)
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
	t.Logf("=== SPRINT 63 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkMemorization_EvaluateExtraction(b *testing.B) {
	auditor := NewAuditor()
	probe := CanaryProbe{ExpectedTail: "confidential string payload"}
	cont := "confidential string payload"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = auditor.EvaluateExtraction(probe, cont)
	}
}
