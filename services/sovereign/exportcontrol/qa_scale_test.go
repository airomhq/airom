package exportcontrol

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeExportScale_50KScreenings(t *testing.T) {
	engine := NewEngine()

	spec := ModelExportSpec{
		ModelName:          "Production-Model",
		TotalTrainingFLOPs: 5e25,
		RecipientEntity:    "Enterprise-Consumer",
		DestinationCountry: "France",
	}

	const numOps = 50000
	start := time.Now()

	for i := 0; i < numOps; i++ {
		res := engine.ScreenModel(spec)
		if res.Requirement != NoLicenseRequired_NLR {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numOps) / duration.Seconds()
	t.Logf("=== SPRINT 68 SCALE: 50K AI EXPORT CONTROL & SANCTIONS SCREENINGS ===")
	t.Logf("Screenings: %d", numOps)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f screenings/sec", opsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentExportStorm_100Workers(t *testing.T) {
	engine := NewEngine()
	spec := ModelExportSpec{
		ModelName:          "Conc-Model",
		RecipientEntity:    "Standard-Org",
		DestinationCountry: "Japan",
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
				res := engine.ScreenModel(spec)
				if res.Requirement != NoLicenseRequired_NLR {
					t.Errorf("unexpected failure")
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
	t.Logf("=== SPRINT 68 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkExport_ScreenModel(b *testing.B) {
	engine := NewEngine()
	spec := ModelExportSpec{ModelName: "Bench", RecipientEntity: "Org", DestinationCountry: "Japan"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.ScreenModel(spec)
	}
}
