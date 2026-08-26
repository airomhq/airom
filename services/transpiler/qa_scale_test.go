package transpiler

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeTranspilerScale_50KDocs(t *testing.T) {
	engine := NewEngine()
	cdxPayload := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"model","type":"model"}]}`)

	req := TranspileRequest{
		SourceFormat: FormatCycloneDX,
		TargetFormat: FormatSPDX3,
		Payload:      cdxPayload,
	}

	const numDocs = 50000
	start := time.Now()
	for i := 0; i < numDocs; i++ {
		res, err := engine.Transpile(req)
		if err != nil || res.ComponentsRead != 1 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	docsPerSec := float64(numDocs) / duration.Seconds()
	t.Logf("=== SPRINT 113 SCALE: 50K AIBOM DOCUMENTS TRANSPILED (CDX <-> SPDX3) ===")
	t.Logf("Documents:  %d", numDocs)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f docs/sec", docsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentTranspilerStorm_100Workers(t *testing.T) {
	engine := NewEngine()
	cdxPayload := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"conc_model"}]}`)
	req := TranspileRequest{
		SourceFormat: FormatCycloneDX,
		TargetFormat: FormatSPDX3,
		Payload:      cdxPayload,
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
				res, err := engine.Transpile(req)
				if err != nil || res.ComponentsRead != 1 {
					errCh <- fmt.Errorf("unexpected failure")
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
	t.Logf("=== SPRINT 113 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkTranspiler_Transpile(b *testing.B) {
	engine := NewEngine()
	cdxPayload := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"bench_model"}]}`)
	req := TranspileRequest{
		SourceFormat: FormatCycloneDX,
		TargetFormat: FormatSPDX3,
		Payload:      cdxPayload,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Transpile(req)
	}
}
