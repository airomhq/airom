package owasp

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_ExtremeOWASPScale_10KComponents(t *testing.T) {
	auditor := NewAuditor()

	const numComps = 10000
	comps := make([]airom.Component, numComps)
	for i := 0; i < numComps; i++ {
		comps[i] = airom.Component{
			ID:   airom.ID(fmt.Sprintf("comp-%06d", i)),
			Kind: airom.KindHostedLLM,
			Name: fmt.Sprintf("model-%d", i),
			Model: &airom.ModelFacet{
				GenerationParams: []airom.BoundParam{{Name: "max_tokens", Value: "2048"}},
			},
		}
	}

	inv := &airom.Inventory{Components: comps}

	start := time.Now()
	scorecard := auditor.Audit(inv)
	duration := time.Since(start)

	if scorecard.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for clean scale inventory")
	}

	compsPerSec := float64(numComps) / duration.Seconds()
	t.Logf("=== SPRINT 48 SCALE: 10K COMPONENTS OWASP AUDITED ===")
	t.Logf("Components: %d", numComps)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f comps/sec", compsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentOWASPStorm_100Workers(t *testing.T) {
	auditor := NewAuditor()
	inv := &airom.Inventory{
		Components: []airom.Component{
			{ID: "c1", Kind: airom.KindHostedLLM, Name: "m1", Model: &airom.ModelFacet{GenerationParams: []airom.BoundParam{{Name: "max_tokens", Value: "100"}}}},
		},
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
				scorecard := auditor.Audit(inv)
				if scorecard.RiskScore != 0.0 {
					errCh <- fmt.Errorf("unexpected risk score")
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
	t.Logf("=== SPRINT 48 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkOWASP_Audit(b *testing.B) {
	auditor := NewAuditor()
	inv := &airom.Inventory{
		Components: []airom.Component{
			{ID: "c1", Kind: airom.KindHostedLLM, Name: "m1", Model: &airom.ModelFacet{GenerationParams: []airom.BoundParam{{Name: "max_tokens", Value: "100"}}}},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auditor.Audit(inv)
	}
}
