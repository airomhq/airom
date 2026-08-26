package huggingface

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeHFScale_50KModels(t *testing.T) {
	connector := NewConnector()

	const numModels = 50000
	models := make([]HFModelCardSpec, numModels)
	for i := 0; i < numModels; i++ {
		models[i] = HFModelCardSpec{
			RepoID:         fmt.Sprintf("author_%d/model_%d", i, i),
			ModelName:      fmt.Sprintf("Model_%d", i),
			License:        "apache-2.0",
			ParameterCount: "7B",
			GGUFVariants:   []string{"Q4_K_M"},
		}
	}

	start := time.Now()
	for i := 0; i < numModels; i++ {
		res := connector.CompileAIBOM(models[i])
		if len(res.Inventory.Components) != 2 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	modelsPerSec := float64(numModels) / duration.Seconds()
	t.Logf("=== SPRINT 109 SCALE: 50K HUGGINGFACE HUB MODEL REPOS COMPILED TO AIBOM ===")
	t.Logf("Models:     %d", numModels)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f models/sec", modelsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentHFStorm_100Workers(t *testing.T) {
	connector := NewConnector()
	spec := HFModelCardSpec{
		RepoID:       "conc_org/conc_model",
		ModelName:    "ConcModel",
		License:      "mit",
		GGUFVariants: []string{"Q8_0"},
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
				res := connector.CompileAIBOM(spec)
				if len(res.Inventory.Components) != 2 {
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
	t.Logf("=== SPRINT 109 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkHF_CompileAIBOM(b *testing.B) {
	connector := NewConnector()
	spec := HFModelCardSpec{
		RepoID:       "bench/model",
		ModelName:    "BenchModel",
		License:      "apache-2.0",
		GGUFVariants: []string{"Q4_K_M"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = connector.CompileAIBOM(spec)
	}
}
