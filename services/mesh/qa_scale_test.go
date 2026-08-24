package mesh

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeMeshScale_500Clusters50KWorkloads(t *testing.T) {
	engine := NewEngine()

	const numClusters = 500
	const workloadsPerCluster = 100

	for i := 0; i < numClusters; i++ {
		cID := fmt.Sprintf("cluster-%03d", i)
		engine.RegisterCluster(ClusterNode{
			ID:       cID,
			Provider: ProviderAWS,
			Region:   "us-west-2",
		})

		var wList []AIWorkload
		for j := 0; j < workloadsPerCluster; j++ {
			wList = append(wList, AIWorkload{
				ID:           fmt.Sprintf("w-%d-%d", i, j),
				ClusterID:    cID,
				Type:         TypeVLLM,
				ModelName:    "meta-llama/Llama-3-8B",
				GPUAllocated: 1,
			})
		}
		_ = engine.IngestWorkloads(cID, wList)
	}

	start := time.Now()
	topo := engine.BuildTopology()
	duration := time.Since(start)

	if len(topo.Clusters) != numClusters || topo.TotalWorkloads != numClusters*workloadsPerCluster {
		t.Fatalf("unexpected topology size: clusters=%d, workloads=%d", len(topo.Clusters), topo.TotalWorkloads)
	}

	workloadsPerSec := float64(topo.TotalWorkloads) / duration.Seconds()
	t.Logf("=== SPRINT 52 SCALE: 500 CLUSTERS & 50K WORKLOADS TOPOLOGY BUILD ===")
	t.Logf("Clusters:   %d", len(topo.Clusters))
	t.Logf("Workloads:  %d", topo.TotalWorkloads)
	t.Logf("Total GPUs: %d", topo.TotalGPUs)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f workloads/sec", workloadsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentMeshStorm_100Workers(t *testing.T) {
	engine := NewEngine()
	const numWorkers = 100
	const iterations = 500

	for i := 0; i < numWorkers; i++ {
		engine.RegisterCluster(ClusterNode{ID: fmt.Sprintf("c-%d", i), Provider: ProviderGCP})
	}

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			cID := fmt.Sprintf("c-%d", workerID)
			for j := 0; j < iterations; j++ {
				err := engine.IngestWorkloads(cID, []AIWorkload{
					{ID: fmt.Sprintf("w-%d-%d", workerID, j), ClusterID: cID, GPUAllocated: 1},
				})
				if err != nil {
					errCh <- err
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

	topo := engine.BuildTopology()
	totalOps := numWorkers * iterations
	duration := time.Since(start)

	if topo.TotalWorkloads != totalOps {
		t.Fatalf("expected %d workloads, got %d", totalOps, topo.TotalWorkloads)
	}

	t.Logf("=== SPRINT 52 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkMesh_BuildTopology(b *testing.B) {
	engine := NewEngine()
	engine.RegisterCluster(ClusterNode{ID: "c1", Provider: ProviderAWS})
	_ = engine.IngestWorkloads("c1", []AIWorkload{{ID: "w1", GPUAllocated: 2}})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.BuildTopology()
	}
}
