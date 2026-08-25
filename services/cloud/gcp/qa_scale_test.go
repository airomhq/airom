package gcp

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeGCPScale_50KEndpoints(t *testing.T) {
	connector := NewConnector()

	const numEndpoints = 50000
	endpoints := make([]VertexEndpointSpec, numEndpoints)
	for i := 0; i < numEndpoints; i++ {
		endpoints[i] = VertexEndpointSpec{
			EndpointID:        fmt.Sprintf("projects/123/locations/us-central1/endpoints/ep-%d", i),
			DisplayName:       fmt.Sprintf("gemini-1.5-pro-%d", i),
			ModelResourceName: "publishers/google/models/gemini-1.5-pro",
			ArtifactGCSURI:    fmt.Sprintf("gs://models-bucket/model-%d.safetensors", i),
			Location:          "us-central1",
			CreatedAt:         time.Now().UTC(),
		}
	}

	start := time.Now()
	res := connector.CompileAIBOM("enterprise-ai", "us-central1", endpoints)
	duration := time.Since(start)

	if res == nil || len(res.Inventory.Components) != numEndpoints*2 {
		t.Fatalf("failed scale compilation")
	}

	epsPerSec := float64(numEndpoints) / duration.Seconds()
	t.Logf("=== SPRINT 78 SCALE: 50K GCP VERTEX AI ENDPOINTS COMPILED ===")
	t.Logf("Endpoints:  %d", numEndpoints)
	t.Logf("Components: %d", len(res.Inventory.Components))
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f endpoints/sec", epsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentGCPStorm_100Workers(t *testing.T) {
	connector := NewConnector()
	endpoints := []VertexEndpointSpec{
		{DisplayName: "gemini-flash", ModelResourceName: "publishers/google/models/gemini-1.5-flash", Location: "us-central1"},
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
				res := connector.CompileAIBOM("proj-1", "us-central1", endpoints)
				if res == nil || len(res.Inventory.Components) != 1 {
					errCh <- fmt.Errorf("worker %d iter %d error", workerID, j)
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
	t.Logf("=== SPRINT 78 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkGCP_CompileAIBOM(b *testing.B) {
	connector := NewConnector()
	endpoints := []VertexEndpointSpec{{DisplayName: "bench-ep", ModelResourceName: "gemini-pro", Location: "us-central1"}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = connector.CompileAIBOM("proj-1", "us-central1", endpoints)
	}
}
