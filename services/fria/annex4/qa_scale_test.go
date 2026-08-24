package annex4

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_ExtremeAnnex4Scale_10KDocuments(t *testing.T) {
	generator := NewGenerator()
	inv := &airom.Inventory{
		Components: []airom.Component{
			{ID: "c1", Kind: airom.KindHostedLLM, Name: "model-a"},
			{ID: "c2", Kind: airom.KindFramework, Name: "framework-b"},
		},
	}

	const numDocs = 10000
	start := time.Now()

	for i := 0; i < numDocs; i++ {
		doc := generator.GenerateTechnicalDoc(
			fmt.Sprintf("AI-System-%d", i),
			"Enterprise Provider",
			"1.0.0",
			"Automated credit evaluation",
			inv,
		)
		if len(doc.Sections) != 6 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	docsPerSec := float64(numDocs) / duration.Seconds()
	t.Logf("=== SPRINT 57 SCALE: 10K EU AI ACT ANNEX IV TECHNICAL DOCUMENTS ===")
	t.Logf("Documents:  %d", numDocs)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f docs/sec", docsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentAnnex4Storm_100Workers(t *testing.T) {
	generator := NewGenerator()
	inv := &airom.Inventory{Components: []airom.Component{{ID: "c1", Kind: airom.KindHostedLLM}}}

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
				doc := generator.GenerateTechnicalDoc("sys", "prov", "v", "purp", inv)
				if len(doc.Sections) != 6 {
					errCh <- fmt.Errorf("unexpected section count: %d", len(doc.Sections))
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
	t.Logf("=== SPRINT 57 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkAnnex4_GenerateTechnicalDoc(b *testing.B) {
	generator := NewGenerator()
	inv := &airom.Inventory{Components: []airom.Component{{ID: "c1", Kind: airom.KindHostedLLM}}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generator.GenerateTechnicalDoc("sys", "prov", "v", "purp", inv)
	}
}
