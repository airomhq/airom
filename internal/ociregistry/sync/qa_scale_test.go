package sync

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeRuleDiffScale_10KRules(t *testing.T) {
	const numRules = 10000
	local := make(map[string][]byte, numRules)
	remote := make(map[string][]byte, numRules)

	for i := 0; i < numRules; i++ {
		key := fmt.Sprintf("rules/rule_%06d.yaml", i)
		if i < 8000 {
			local[key] = []byte(fmt.Sprintf("pattern: v1_%d", i))
			remote[key] = []byte(fmt.Sprintf("pattern: v1_%d", i)) // unchanged
		} else if i < 9000 {
			local[key] = []byte(fmt.Sprintf("pattern: v1_%d", i))
			remote[key] = []byte(fmt.Sprintf("pattern: v2_%d", i)) // modified
		} else {
			remote[key] = []byte(fmt.Sprintf("pattern: v2_%d", i)) // added
		}
	}

	start := time.Now()
	delta := ComputeRuleDiff(local, remote)
	duration := time.Since(start)

	if len(delta.Modified) != 1000 || len(delta.Added) != 1000 {
		t.Fatalf("unexpected delta counts: mod=%d, add=%d", len(delta.Modified), len(delta.Added))
	}

	rulesPerSec := float64(numRules) / duration.Seconds()
	t.Logf("=== SPRINT 41 SCALE: 10K DIFFERENTIAL RULE COMPUTATIONS ===")
	t.Logf("Rules:      %d (1K mod, 1K add, 8K unchanged)", numRules)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f rules/sec", rulesPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentDiffStorm_100Workers(t *testing.T) {
	local := map[string][]byte{
		"r1.yaml": []byte("p: 1"),
		"r2.yaml": []byte("p: 2"),
	}
	remote := map[string][]byte{
		"r1.yaml": []byte("p: 1"),
		"r2.yaml": []byte("p: 3"),
		"r3.yaml": []byte("p: 4"),
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
				delta := ComputeRuleDiff(local, remote)
				if len(delta.Added) != 1 || len(delta.Modified) != 1 {
					errCh <- fmt.Errorf("worker %d iter %d invalid delta", workerID, j)
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
	t.Logf("=== SPRINT 41 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkSync_Diff10KRules(b *testing.B) {
	local := map[string][]byte{"r.yaml": []byte("old")}
	remote := map[string][]byte{"r.yaml": []byte("new")}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeRuleDiff(local, remote)
	}
}
