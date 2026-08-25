package pdf

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremePDFScale_10KDocuments(t *testing.T) {
	generator := NewGenerator()
	spec := DocumentSpec{
		Title:            "Scale Test Dossier",
		OrganizationName: "Scale Org",
		RepositoryName:   "scale/repo",
		FrameworkName:    "Colorado SB 24-205",
		ExecutiveSummary: "Annual impact assessment summary.",
		TotalComponents:  100,
		ControlsMet:      95,
		GapsIdentified:   5,
		GeneratedAt:      time.Now().UTC(),
	}

	const numDocs = 10000
	start := time.Now()

	for i := 0; i < numDocs; i++ {
		res := generator.GeneratePDF(spec)
		if res == nil || len(res.PDFBytes) == 0 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	docsPerSec := float64(numDocs) / duration.Seconds()
	t.Logf("=== SPRINT 84 SCALE: 10K EXECUTIVE COMPLIANCE PDFS GENERATED ===")
	t.Logf("Documents:  %d", numDocs)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f pdfs/sec", docsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentPDFStorm_100Workers(t *testing.T) {
	generator := NewGenerator()
	spec := DocumentSpec{
		Title:            "Conc Dossier",
		OrganizationName: "Conc Org",
		ExecutiveSummary: "Summary",
		GeneratedAt:      time.Now().UTC(),
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
				res := generator.GeneratePDF(spec)
				if res == nil || res.SizeBytes == 0 {
					t.Errorf("empty pdf")
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
	t.Logf("=== SPRINT 84 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkPDF_GeneratePDF(b *testing.B) {
	generator := NewGenerator()
	spec := DocumentSpec{Title: "Bench", ExecutiveSummary: "Bench Summary"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generator.GeneratePDF(spec)
	}
}
