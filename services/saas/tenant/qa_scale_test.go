package tenant

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeTenantScale_50KQuotaChecks(t *testing.T) {
	manager := NewManager()
	_, _ = manager.CreateOrganization("org-scale", "Scale Org", TierSovereign)

	const numScans = 50000
	start := time.Now()

	for i := 0; i < numScans; i++ {
		err := manager.RecordScan("org-scale")
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
	}
	duration := time.Since(start)

	scansPerSec := float64(numScans) / duration.Seconds()
	t.Logf("=== SPRINT 82 SCALE: 50K SAAS TENANT SCAN QUOTA CHECKS ===")
	t.Logf("Scans:      %d", numScans)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f scans/sec", scansPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentTenantStorm_100Workers(t *testing.T) {
	manager := NewManager()

	for i := 0; i < 100; i++ {
		_, _ = manager.CreateOrganization(fmt.Sprintf("org-conc-%d", i), "Conc Org", TierSovereign)
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
			orgID := fmt.Sprintf("org-conc-%d", workerID)
			for j := 0; j < iterations; j++ {
				err := manager.RecordScan(orgID)
				if err != nil {
					errCh <- fmt.Errorf("worker %d iter %d scan error: %w", workerID, j, err)
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
	t.Logf("=== SPRINT 82 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkTenant_RecordScan(b *testing.B) {
	manager := NewManager()
	_, _ = manager.CreateOrganization("org-bench", "Bench Org", TierSovereign)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.RecordScan("org-bench")
	}
}
