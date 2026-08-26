package structured

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeStructuredScale_50KCalls(t *testing.T) {
	detector := NewDetector()

	const numCalls = 50000
	calls := make([]StructuredCallSpec, numCalls)
	for i := 0; i < numCalls; i++ {
		calls[i] = StructuredCallSpec{
			EngineType:        EngineOutlines,
			SchemaName:        fmt.Sprintf("Schema_%d", i),
			HasTypeValidation: true,
			EnforcesGrammar:   true,
		}
	}

	start := time.Now()
	for i := 0; i < numCalls; i++ {
		res := detector.EvaluateCall(calls[i])
		if !res.IsGuaranteed {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	callsPerSec := float64(numCalls) / duration.Seconds()
	t.Logf("=== SPRINT 107 SCALE: 50K STRUCTURED OUTPUT CALLS EVALUATED ===")
	t.Logf("Calls:      %d", numCalls)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f calls/sec", callsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentStructuredStorm_100Workers(t *testing.T) {
	detector := NewDetector()
	spec := StructuredCallSpec{
		EngineType:        EngineInstructor,
		SchemaName:        "ConcSchema",
		HasTypeValidation: true,
		MaxRetries:        2,
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
				res := detector.EvaluateCall(spec)
				if !res.IsGuaranteed {
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
	t.Logf("=== SPRINT 107 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkStructured_EvaluateCall(b *testing.B) {
	detector := NewDetector()
	spec := StructuredCallSpec{
		EngineType:        EngineOutlines,
		SchemaName:        "BenchSchema",
		HasTypeValidation: true,
		EnforcesGrammar:   true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.EvaluateCall(spec)
	}
}
