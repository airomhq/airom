package azure

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeAzureScale_50KDeployments(t *testing.T) {
	connector := NewConnector()

	const numDeployments = 50000
	deployments := make([]AzureDeploymentSpec, numDeployments)
	for i := 0; i < numDeployments; i++ {
		deployments[i] = AzureDeploymentSpec{
			DeploymentName: fmt.Sprintf("dep-%d", i),
			ModelName:      fmt.Sprintf("gpt-4o-%d", i),
			ModelVersion:   "2024-05-13",
			CapacityTPM:    100000,
			SubscriptionID: "sub-123",
			ResourceGroup:  "rg-ai",
			Region:         "eastus",
			CreatedAt:      time.Now().UTC(),
		}
	}

	start := time.Now()
	res := connector.CompileAIBOM("sub-123", "tenant-456", deployments)
	duration := time.Since(start)

	if res == nil || len(res.Inventory.Components) != numDeployments {
		t.Fatalf("failed scale compilation")
	}

	depsPerSec := float64(numDeployments) / duration.Seconds()
	t.Logf("=== SPRINT 77 SCALE: 50K AZURE AI DEPLOYMENTS COMPILED ===")
	t.Logf("Deployments: %d", numDeployments)
	t.Logf("Latency:     %v", duration)
	t.Logf("Throughput:  %.2f deployments/sec", depsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentAzureStorm_100Workers(t *testing.T) {
	connector := NewConnector()
	deployments := []AzureDeploymentSpec{
		{DeploymentName: "dep-1", ModelName: "gpt-4o", ModelVersion: "2024-05-13", Region: "eastus"},
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
				res := connector.CompileAIBOM("sub-123", "tenant-456", deployments)
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
	t.Logf("=== SPRINT 77 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkAzure_CompileAIBOM(b *testing.B) {
	connector := NewConnector()
	deployments := []AzureDeploymentSpec{{DeploymentName: "bench-dep", ModelName: "gpt-4o", Region: "eastus"}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = connector.CompileAIBOM("sub-123", "tenant-456", deployments)
	}
}
