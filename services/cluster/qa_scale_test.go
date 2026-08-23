package cluster

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestQA_ExtremeClusterScale_1KNodes stress-tests cluster operations across 1,000 nodes and 100,000 heartbeats.
func TestQA_ExtremeClusterScale_1KNodes(t *testing.T) {
	const nodeCount = 1_000
	const heartbeatsPerNode = 100
	const totalHeartbeats = nodeCount * heartbeatsPerNode // 100,000 heartbeats

	t.Logf("=== Starting Extreme Scale Cluster Test: %d Nodes, %d Total Heartbeats ===", nodeCount, totalHeartbeats)

	mgr := NewClusterManager("scale-cluster")

	for i := 0; i < nodeCount; i++ {
		_ = mgr.RegisterNode(ClusterNode{
			NodeID:   fmt.Sprintf("node_%04d", i),
			Hostname: fmt.Sprintf("airom-node-%04d.prod.cloud", i),
			Port:     8080,
		})
	}

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()

	for h := 0; h < heartbeatsPerNode; h++ {
		for i := 0; i < nodeCount; i++ {
			nodeID := fmt.Sprintf("node_%04d", i)
			_ = mgr.RecordHeartbeat(nodeID, []string{"gateway", "compliancedb"})
		}
	}

	state := mgr.GetClusterState()
	duration := time.Since(start)

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	if state.TotalNodes != nodeCount {
		t.Fatalf("expected %d nodes in cluster state, got %d", nodeCount, state.TotalNodes)
	}

	hbPerSec := float64(totalHeartbeats) / duration.Seconds()

	t.Logf("=== Scale Cluster Results ===")
	t.Logf("Nodes: %d | Heartbeats Processed: %d | Quorum: %s", nodeCount, totalHeartbeats, state.Quorum)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f heartbeats/sec", hbPerSec)
	t.Logf("Heap Alloc Delta: %.2f KB", float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/1024.0)

	if duration >= 5*time.Second {
		t.Fatalf("Performance violation: 100K heartbeats took %v (threshold: < 5.0s)", duration)
	}
}

// TestQA_ConcurrentClusterStorm_100Workers tests concurrent heartbeats and state requests with 100 goroutines.
func TestQA_ConcurrentClusterStorm_100Workers(t *testing.T) {
	const numWorkers = 100
	const reqsPerWorker = 50
	const totalReqs = numWorkers * reqsPerWorker // 5,000 requests

	t.Logf("=== Starting Concurrent Cluster Test: %d Workers, %d Total Requests ===", numWorkers, totalReqs)

	mgr := NewClusterManager("concurrent-cluster")
	for i := 0; i < 10; i++ {
		_ = mgr.RegisterNode(ClusterNode{
			NodeID:   fmt.Sprintf("node_%d", i),
			Hostname: fmt.Sprintf("host_%d", i),
			Port:     8080,
		})
	}

	var (
		completedCount int64
		failedCount    int64
		wg             sync.WaitGroup
	)

	start := time.Now()

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < reqsPerWorker; i++ {
				nodeID := fmt.Sprintf("node_%d", (workerID+i)%10)
				err := mgr.RecordHeartbeat(nodeID, []string{"all"})
				state := mgr.GetClusterState()
				if err != nil || state == nil || state.StateChecksum == "" {
					atomic.AddInt64(&failedCount, 1)
				} else {
					atomic.AddInt64(&completedCount, 1)
				}
			}
		}(w)
	}

	wg.Wait()
	duration := time.Since(start)
	throughput := float64(totalReqs) / duration.Seconds()

	t.Logf("=== Concurrent Cluster Results ===")
	t.Logf("Requests Completed: %d | Failures: %d", completedCount, failedCount)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f reqs/sec", throughput)

	if failedCount > 0 {
		t.Fatalf("expected 0 cluster failures, got %d", failedCount)
	}
	if completedCount != int64(totalReqs) {
		t.Fatalf("expected %d completed requests, got %d", totalReqs, completedCount)
	}
	if duration >= 10*time.Second {
		t.Fatalf("Performance violation: Concurrent cluster requests took %v (threshold: < 10.0s)", duration)
	}
}

// BenchmarkScale_ClusterHeartbeat benchmarks single heartbeat.
func BenchmarkScale_ClusterHeartbeat(b *testing.B) {
	mgr := NewClusterManager("bench-cluster")
	_ = mgr.RegisterNode(ClusterNode{NodeID: "bench-node", Hostname: "host", Port: 8080})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = mgr.RecordHeartbeat("bench-node", []string{"service"})
	}
}
