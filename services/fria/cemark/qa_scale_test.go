package cemark

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeCEMarkScale_10KDeclarations(t *testing.T) {
	generator := NewGenerator()

	const numDocs = 10000
	start := time.Now()

	for i := 0; i < numDocs; i++ {
		doc := generator.GenerateDeclaration(
			fmt.Sprintf("AI-System-%d", i),
			"EuroCorp SA",
			"Brussels, Belgium",
			"Officer",
			"CCO",
			"Brussels",
		)
		if !doc.CEMarkAffixed {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	docsPerSec := float64(numDocs) / duration.Seconds()
	t.Logf("=== SPRINT 58 SCALE: 10K EU AI ACT DECLARATIONS OF CONFORMITY ===")
	t.Logf("Declarations: %d", numDocs)
	t.Logf("Latency:      %v", duration)
	t.Logf("Throughput:   %.2f docs/sec", docsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentCEMarkStorm_100Workers(t *testing.T) {
	generator := NewGenerator()

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
				doc := generator.GenerateDeclaration("sys", "prov", "addr", "signer", "role", "place")
				if !doc.CEMarkAffixed {
					errCh <- fmt.Errorf("CE mark missing")
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
	t.Logf("=== SPRINT 58 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:    %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkCEMark_GenerateDeclaration(b *testing.B) {
	generator := NewGenerator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generator.GenerateDeclaration("sys", "prov", "addr", "signer", "role", "place")
	}
}
