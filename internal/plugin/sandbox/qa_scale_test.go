package sandbox

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeSandboxScale_100KValidations(t *testing.T) {
	root := filepath.Clean("/workspace/enterprise-app")
	policy := DefaultStrictPolicy(root)
	validator := NewPolicyValidator(policy)

	const numOps = 100000
	validPath := filepath.Join(root, "src/engine/worker.go")

	start := time.Now()
	for i := 0; i < numOps; i++ {
		if err := validator.ValidateReadAccess(validPath); err != nil {
			t.Fatalf("failed at iter %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numOps) / duration.Seconds()
	t.Logf("=== SPRINT 44 SCALE: 100K SANDBOX POLICY VALIDATIONS ===")
	t.Logf("Validations: %d", numOps)
	t.Logf("Latency:     %v", duration)
	t.Logf("Throughput:  %.2f ops/sec", opsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentSandboxStorm_100Workers(t *testing.T) {
	root := filepath.Clean("/workspace/repo")
	policy := DefaultStrictPolicy(root)
	validator := NewPolicyValidator(policy)

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			path := filepath.Join(root, fmt.Sprintf("sub/file_%d.py", workerID))
			for j := 0; j < iterations; j++ {
				if err := validator.ValidateReadAccess(path); err != nil {
					errCh <- fmt.Errorf("worker %d iter %d error: %w", workerID, j, err)
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
	t.Logf("=== SPRINT 44 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:   %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkSandbox_ValidateReadAccess(b *testing.B) {
	root := filepath.Clean("/workspace/repo")
	policy := DefaultStrictPolicy(root)
	validator := NewPolicyValidator(policy)
	path := filepath.Join(root, "src/main.py")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateReadAccess(path)
	}
}
