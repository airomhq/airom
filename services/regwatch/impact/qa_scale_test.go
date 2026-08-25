package impact

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_ExtremeImpactScale_50KComponents(t *testing.T) {
	evaluator := NewEvaluator()

	const numComponents = 50000
	comps := make([]airom.Component, numComponents)
	for i := 0; i < numComponents; i++ {
		comps[i] = airom.Component{
			ID:   airom.ID(fmt.Sprintf("comp-%d", i)),
			Kind: airom.KindHostedLLM,
			Name: fmt.Sprintf("model-%d", i),
			Model: &airom.ModelFacet{
				ParamCount: airom.KnownInt64(int64(i * 1_000_000_000)),
			},
		}
	}
	inv := &airom.Inventory{Components: comps}

	start := time.Now()
	res := evaluator.EvaluateInventory("CA-SB1047", inv)
	duration := time.Since(start)

	if res == nil || res.TotalComponents != numComponents {
		t.Fatalf("failed scale impact evaluation")
	}

	compsPerSec := float64(numComponents) / duration.Seconds()
	t.Logf("=== SPRINT 86 SCALE: 50K COMPONENTS EVALUATED FOR LEGISLATIVE BLAST RADIUS ===")
	t.Logf("Components: %d", numComponents)
	t.Logf("Affected:   %d", res.AffectedCount)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f comps/sec", compsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentImpactStorm_100Workers(t *testing.T) {
	evaluator := NewEvaluator()
	inv := &airom.Inventory{
		Components: []airom.Component{
			{ID: "c-1", Kind: airom.KindHostedLLM, Name: "gpt-4o"},
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
				res := evaluator.EvaluateInventory("MA-H4887", inv)
				if res == nil || res.TotalComponents != 1 {
					errCh <- fmt.Errorf("worker %d iter %d error", workerID, j)
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
	t.Logf("=== SPRINT 86 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkImpact_EvaluateInventory(b *testing.B) {
	evaluator := NewEvaluator()
	inv := &airom.Inventory{
		Components: []airom.Component{{ID: "c", Kind: airom.KindHostedLLM}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = evaluator.EvaluateInventory("CA-SB1047", inv)
	}
}
