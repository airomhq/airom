package edge

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeEdgeScale_50KModels(t *testing.T) {
	verifier := NewVerifier()

	const numModels = 50000
	models := make([]EdgeModelBinding, numModels)
	for i := 0; i < numModels; i++ {
		models[i] = EdgeModelBinding{
			ModelName:          fmt.Sprintf("edge_model_%d.engine", i),
			Platform:           PlatformTensorRT,
			Quantization:       "INT8",
			HasRingBufferGuard: true,
			MemorySpec: MemoryBoundarySpec{
				MaxSRAMUsageBytes:       4 * 1024 * 1024,
				ZeroCopyVerified:        true,
				DeterministicDeadlineMs: 10,
			},
		}
	}

	start := time.Now()
	for i := 0; i < numModels; i++ {
		res := verifier.VerifyModel(models[i])
		if !res.IsSafe {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	modelsPerSec := float64(numModels) / duration.Seconds()
	t.Logf("=== SPRINT 92 SCALE: 50K EDGE NPU MODELS VERIFIED ===")
	t.Logf("Models:     %d", numModels)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f models/sec", modelsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentEdgeStorm_100Workers(t *testing.T) {
	verifier := NewVerifier()
	binding := EdgeModelBinding{
		ModelName:          "conc_edge.hef",
		Platform:           PlatformAppleANE,
		Quantization:       "INT8",
		HasRingBufferGuard: true,
		MemorySpec: MemoryBoundarySpec{
			MaxSRAMUsageBytes:       2 * 1024 * 1024,
			ZeroCopyVerified:        true,
			DeterministicDeadlineMs: 5,
		},
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
				res := verifier.VerifyModel(binding)
				if !res.IsSafe {
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
	t.Logf("=== SPRINT 92 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkEdge_VerifyModel(b *testing.B) {
	verifier := NewVerifier()
	binding := EdgeModelBinding{
		ModelName:          "bench.engine",
		Platform:           PlatformTensorRT,
		HasRingBufferGuard: true,
		MemorySpec:         MemoryBoundarySpec{ZeroCopyVerified: true, DeterministicDeadlineMs: 10},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.VerifyModel(binding)
	}
}
