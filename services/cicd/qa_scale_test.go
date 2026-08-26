package cicd

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeCICDScale_50KWorkflows(t *testing.T) {
	compiler := NewCompiler()
	spec := PipelineSpec{
		Platform:     PlatformGitHubActions,
		Framework:    "colorado-ai-act",
		FailOnGaps:   true,
		TargetBranch: "main",
	}

	const numWorkflows = 50000
	start := time.Now()
	for i := 0; i < numWorkflows; i++ {
		res := compiler.Compile(spec)
		if len(res.Content) == 0 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	wfPerSec := float64(numWorkflows) / duration.Seconds()
	t.Logf("=== SPRINT 114 SCALE: 50K CI/CD WORKFLOWS & PRE-COMMIT HOOKS SYNTHESIZED ===")
	t.Logf("Workflows:  %d", numWorkflows)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f workflows/sec", wfPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentCICDStorm_100Workers(t *testing.T) {
	compiler := NewCompiler()
	spec := PipelineSpec{
		Platform:  PlatformGitLabCI,
		Framework: "eu-ai-act",
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
				res := compiler.Compile(spec)
				if len(res.Content) == 0 {
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
	t.Logf("=== SPRINT 114 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkCICD_Compile(b *testing.B) {
	compiler := NewCompiler()
	spec := PipelineSpec{
		Platform:  PlatformGitHubActions,
		Framework: "colorado-ai-act",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = compiler.Compile(spec)
	}
}
