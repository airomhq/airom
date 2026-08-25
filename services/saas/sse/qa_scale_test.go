package sse

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeSSEScale_50KPublishes(t *testing.T) {
	b := NewBroadcaster(100)

	// Subscribe 100 clients across 10 orgs
	for i := 0; i < 100; i++ {
		orgID := fmt.Sprintf("org-%d", i%10)
		_ = b.Subscribe(fmt.Sprintf("client-%d", i), orgID)
	}

	const numPublishes = 50000
	start := time.Now()

	for i := 0; i < numPublishes; i++ {
		orgID := fmt.Sprintf("org-%d", i%10)
		_ = b.Publish(orgID, EventAnomalyDetected, "Anomaly alert")
	}
	duration := time.Since(start)

	pubPerSec := float64(numPublishes) / duration.Seconds()
	t.Logf("=== SPRINT 83 SCALE: 50K SSE BROADCAST PUBLISHES ===")
	t.Logf("Publishes:  %d", numPublishes)
	t.Logf("Clients:    %d", b.ClientCount())
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f events/sec", pubPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentSSEStorm_100Workers(t *testing.T) {
	b := NewBroadcaster(500)

	for i := 0; i < 100; i++ {
		_ = b.Subscribe(fmt.Sprintf("conc-client-%d", i), fmt.Sprintf("conc-org-%d", i))
	}

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			orgID := fmt.Sprintf("conc-org-%d", workerID)
			for j := 0; j < iterations; j++ {
				_ = b.Publish(orgID, EventScanCompleted, "Done")
			}
		}(i)
	}

	wg.Wait()

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 83 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkSSE_Publish(b *testing.B) {
	broadcaster := NewBroadcaster(1000)
	_ = broadcaster.Subscribe("bench-client", "bench-org")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = broadcaster.Publish("bench-org", EventScanCompleted, "Data")
	}
}
