package ghg

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeGHGScale_50KReports(t *testing.T) {
	accountant := NewAccountant()

	const numReports = 50000
	start := time.Now()

	for i := 0; i < numReports; i++ {
		report := accountant.GenerateStatutoryReport(
			fmt.Sprintf("Corp-%d", i),
			2026,
			Grid_US_CAISO_California,
			50000.0,
			25000.0,
		)
		if report.TotalEmissionsTonsCO2 <= 0 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	reportsPerSec := float64(numReports) / duration.Seconds()
	t.Logf("=== SPRINT 60 SCALE: 50K STATUTORY AI GHG CARBON REPORTS ===")
	t.Logf("Reports:    %d", numReports)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f reports/sec", reportsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentGHGStorm_100Workers(t *testing.T) {
	accountant := NewAccountant()

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
				rep := accountant.GenerateStatutoryReport("corp", 2026, Grid_US_ERCOT_Texas, 1000.0, 500.0)
				if rep.TotalEmissionsTonsCO2 <= 0 {
					errCh <- fmt.Errorf("unexpected zero emissions")
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
	t.Logf("=== SPRINT 60 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkGHG_GenerateStatutoryReport(b *testing.B) {
	accountant := NewAccountant()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = accountant.GenerateStatutoryReport("corp", 2026, Grid_US_CAISO_California, 10000.0, 5000.0)
	}
}
