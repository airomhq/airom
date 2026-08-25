package remediation

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeRemediationScale_50KFiles(t *testing.T) {
	engine := NewEngine()

	const numFiles = 50000
	files := make(map[string]string, numFiles)
	for i := 0; i < numFiles; i++ {
		files[fmt.Sprintf("src/service_%d.py", i)] = "model = 'gpt-3.5-turbo-0613'\n# active LLM call\n"
	}

	start := time.Now()
	plan := engine.CreateRemediationPlan("scale-org/repo", files)
	duration := time.Since(start)

	if plan == nil || len(plan.Patches) != numFiles {
		t.Fatalf("failed scale remediation plan generation")
	}

	filesPerSec := float64(numFiles) / duration.Seconds()
	t.Logf("=== SPRINT 80 SCALE: 50K AUTOMATED MODEL UPGRADE PATCHES ===")
	t.Logf("Files:      %d", numFiles)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f files/sec", filesPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentRemediationStorm_100Workers(t *testing.T) {
	engine := NewEngine()
	files := map[string]string{
		"src/app.py": "model = 'gpt-3.5-turbo'\n",
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
				plan := engine.CreateRemediationPlan("repo-conc", files)
				if plan == nil || len(plan.Patches) != 1 {
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
	t.Logf("=== SPRINT 80 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkRemediation_PatchGeneration(b *testing.B) {
	engine := NewEngine()
	files := map[string]string{"src/app.py": "model = 'gpt-3.5-turbo'\n"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.CreateRemediationPlan("bench-repo", files)
	}
}
