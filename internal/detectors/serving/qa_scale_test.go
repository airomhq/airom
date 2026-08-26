package serving

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeServingScale_50KConfigs(t *testing.T) {
	detector := NewDetector()

	const numConfigs = 50000
	configs := make([]ServingConfigSpec, numConfigs)
	for i := 0; i < numConfigs; i++ {
		configs[i] = ServingConfigSpec{
			EngineType:         EngineVLLM,
			ModelName:          fmt.Sprintf("org/model_%d", i),
			TensorParallelSize: 2,
			GPUMemoryUtil:      0.85,
			MaxModelLen:        8192,
		}
	}

	start := time.Now()
	for i := 0; i < numConfigs; i++ {
		res := detector.EvaluateConfig(configs[i])
		if !res.IsConformant {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	configsPerSec := float64(numConfigs) / duration.Seconds()
	t.Logf("=== SPRINT 106 SCALE: 50K SERVING ENGINE CONFIGS EVALUATED ===")
	t.Logf("Configs:    %d", numConfigs)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f configs/sec", configsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentServingStorm_100Workers(t *testing.T) {
	detector := NewDetector()
	cfg := ServingConfigSpec{
		EngineType:         EngineTensorRTLLM,
		ModelName:          "conc_model",
		TensorParallelSize: 4,
		GPUMemoryUtil:      0.90,
		MaxModelLen:        16384,
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
				res := detector.EvaluateConfig(cfg)
				if !res.IsConformant {
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
	t.Logf("=== SPRINT 106 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkServing_EvaluateConfig(b *testing.B) {
	detector := NewDetector()
	cfg := ServingConfigSpec{
		EngineType:         EngineVLLM,
		ModelName:          "bench_model",
		TensorParallelSize: 1,
		GPUMemoryUtil:      0.80,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.EvaluateConfig(cfg)
	}
}
