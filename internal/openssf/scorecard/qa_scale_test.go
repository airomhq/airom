package scorecard

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_ExtremeScorecardScale_50KComponents(t *testing.T) {
	evaluator := NewEvaluator()

	const numComponents = 50000
	comps := make([]airom.Component, numComponents)
	for i := 0; i < numComponents; i++ {
		comps[i] = airom.Component{
			ID:   airom.ID(fmt.Sprintf("comp-%d", i)),
			Kind: airom.KindHostedLLM,
			Name: fmt.Sprintf("model-%d", i),
			PURL: "pkg:huggingface/model@1.0",
			Licenses: []airom.License{
				{SPDXID: "MIT"},
			},
		}
	}
	inv := &airom.Inventory{Components: comps}

	start := time.Now()
	res := evaluator.EvaluateInventory(inv)
	duration := time.Since(start)

	if res == nil || res.TotalModels != numComponents {
		t.Fatalf("failed scale scorecard evaluation")
	}

	compsPerSec := float64(numComponents) / duration.Seconds()
	t.Logf("=== SPRINT 88 SCALE: 50K OPENSSF AI MODEL SECURITY SCORECARDS ===")
	t.Logf("Models:     %d", numComponents)
	t.Logf("Passing:    %d", res.PassingModels)
	t.Logf("Avg Score:  %.1f", res.AverageScore)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f models/sec", compsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentScorecardStorm_100Workers(t *testing.T) {
	evaluator := NewEvaluator()
	comp := airom.Component{
		ID:   "comp-conc",
		Kind: airom.KindHostedLLM,
		PURL: "pkg:model/conc",
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
				sc := evaluator.EvaluateComponent(comp)
				if sc.OverallScore == 0 {
					errCh <- fmt.Errorf("invalid zero score")
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
	t.Logf("=== SPRINT 88 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkScorecard_EvaluateComponent(b *testing.B) {
	evaluator := NewEvaluator()
	comp := airom.Component{
		ID:   "bench-c",
		Kind: airom.KindHostedLLM,
		Licenses: []airom.License{
			{SPDXID: "Apache-2.0"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = evaluator.EvaluateComponent(comp)
	}
}
