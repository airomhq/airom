package serverless

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeServerlessScale_50KEndpoints(t *testing.T) {
	ingestor := NewIngestor()

	const numEndpoints = 50000
	endpoints := make([]EndpointSpec, numEndpoints)
	for i := 0; i < numEndpoints; i++ {
		endpoints[i] = EndpointSpec{
			Provider:       ProviderGroq,
			ModelName:      fmt.Sprintf("groq-model-%d", i),
			HardwareEngine: "LPU",
			ContextTokens:  32768,
			PricingPerMIn:  0.20,
			PricingPerMOut: 0.20,
		}
	}

	start := time.Now()
	res := ingestor.CompileAIBOM(endpoints)
	duration := time.Since(start)

	if len(res.Inventory.Components) != numEndpoints {
		t.Fatalf("expected %d components, got %d", numEndpoints, len(res.Inventory.Components))
	}

	epsPerSec := float64(numEndpoints) / duration.Seconds()
	t.Logf("=== SPRINT 111 SCALE: 50K SERVERLESS CLOUD ENDPOINTS COMPILED TO AIBOM ===")
	t.Logf("Endpoints:  %d", numEndpoints)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f endpoints/sec", epsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentServerlessStorm_100Workers(t *testing.T) {
	ingestor := NewIngestor()
	endpoints := []EndpointSpec{
		{
			Provider:       ProviderTogetherAI,
			ModelName:      "conc_together_model",
			HardwareEngine: "H100",
			ContextTokens:  16384,
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
				res := ingestor.CompileAIBOM(endpoints)
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
	t.Logf("=== SPRINT 111 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkServerless_CompileAIBOM(b *testing.B) {
	ingestor := NewIngestor()
	endpoints := []EndpointSpec{
		{Provider: ProviderFireworks, ModelName: "fireworks-llama-3"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ingestor.CompileAIBOM(endpoints)
	}
}
