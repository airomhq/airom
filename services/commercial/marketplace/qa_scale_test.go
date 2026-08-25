package marketplace

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeMarketplaceScale_100KRecords(t *testing.T) {
	meter := NewMeter()

	const numRecords = 100000
	start := time.Now()

	for i := 0; i < numRecords; i++ {
		_, err := meter.IngestUsage(ProviderGCP, "cust-scale", DimensionModelScans, 1, "")
		if err != nil {
			t.Fatalf("failed at iter %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	batch := meter.FlushBatch(ProviderGCP)
	if batch == nil || batch.RecordCount != numRecords {
		t.Fatalf("failed to flush scale batch")
	}

	recsPerSec := float64(numRecords) / duration.Seconds()
	t.Logf("=== SPRINT 89 SCALE: 100K CLOUD MARKETPLACE USAGE RECORDS METERED ===")
	t.Logf("Records:    %d", numRecords)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f records/sec", recsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentMarketplaceStorm_100Workers(t *testing.T) {
	meter := NewMeter()

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
				tok := fmt.Sprintf("worker-%d-token-%d", workerID, j)
				_, err := meter.IngestUsage(ProviderAWS, fmt.Sprintf("cust-%d", workerID), DimensionModelScans, 1, tok)
				if err != nil {
					errCh <- fmt.Errorf("worker %d iter %d error: %w", workerID, j, err)
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
	t.Logf("=== SPRINT 89 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkMarketplace_IngestUsage(b *testing.B) {
	meter := NewMeter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = meter.IngestUsage(ProviderAWS, "bench-cust", DimensionModelScans, 1, "")
	}
}
