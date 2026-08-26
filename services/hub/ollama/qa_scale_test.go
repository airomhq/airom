package ollama

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeOllamaScale_50KModels(t *testing.T) {
	syncer := NewSyncer()

	const numModels = 50000
	models := make([]OllamaModelSpec, numModels)
	for i := 0; i < numModels; i++ {
		models[i] = OllamaModelSpec{
			Name:              fmt.Sprintf("model_%d:latest", i),
			Digest:            "sha256:123456",
			SizeBytes:         4000000000,
			ParameterSize:     "8B",
			QuantizationLevel: "Q4_0",
		}
	}

	start := time.Now()
	res := syncer.CompileAIBOM("http://localhost:11434", models)
	duration := time.Since(start)

	if len(res.Inventory.Components) != numModels {
		t.Fatalf("expected %d components, got %d", numModels, len(res.Inventory.Components))
	}

	modelsPerSec := float64(numModels) / duration.Seconds()
	t.Logf("=== SPRINT 110 SCALE: 50K OLLAMA LOCAL MODELS COMPILED TO AIBOM ===")
	t.Logf("Models:     %d", numModels)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f models/sec", modelsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentOllamaStorm_100Workers(t *testing.T) {
	syncer := NewSyncer()
	models := []OllamaModelSpec{
		{
			Name:              "conc_model:latest",
			Digest:            "sha256:abcdef",
			SizeBytes:         2000000000,
			QuantizationLevel: "Q8_0",
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
				res := syncer.CompileAIBOM("http://localhost:11434", models)
				if len(res.Inventory.Components) != 1 {
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
	t.Logf("=== SPRINT 110 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkOllama_CompileAIBOM(b *testing.B) {
	syncer := NewSyncer()
	models := []OllamaModelSpec{
		{Name: "bench:latest", QuantizationLevel: "Q4_K_M"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = syncer.CompileAIBOM("http://localhost:11434", models)
	}
}
