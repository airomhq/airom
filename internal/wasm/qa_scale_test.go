package wasm

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeWASMScale_100KInvocations(t *testing.T) {
	engine := NewEngine(DefaultSandboxConfig())
	defer engine.Close()

	const numOps = 100000
	code := []byte(`llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.0)`)

	start := time.Now()
	for i := 0; i < numOps; i++ {
		_, _, metrics, err := engine.Execute(context.Background(), LangPython, code, func(ctx context.Context, c []byte) (*ASTNode, []CallSite, error) {
			return &ASTNode{Type: "call", Text: "ChatOpenAI"}, nil, nil
		})
		if err != nil || metrics.Status != StatusSuccess {
			t.Fatalf("failed at iter %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numOps) / duration.Seconds()
	t.Logf("=== SPRINT 35 SCALE: 100K SANDBOXED WASM INVOCATIONS ===")
	t.Logf("Invocations: %d", numOps)
	t.Logf("Latency:     %v", duration)
	t.Logf("Throughput:  %.2f ops/sec", opsPerSec)

	if duration > 3*time.Second {
		t.Errorf("expected execution < 3s, took %v", duration)
	}
}

func TestQA_ConcurrentWASMStorm_100Workers(t *testing.T) {
	cfg := DefaultSandboxConfig()
	cfg.TimeoutPerFile = 2 * time.Second
	engine := NewEngine(cfg)
	defer engine.Close()

	const numWorkers = 100
	const iterations = 500
	code := []byte(`import torch; model = torch.load("weights.pt")`)

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _, metrics, err := engine.Execute(context.Background(), LangPython, code, func(ctx context.Context, c []byte) (*ASTNode, []CallSite, error) {
					return &ASTNode{Type: "import", Text: "torch"}, nil, nil
				})
				if err != nil || metrics.Status != StatusSuccess {
					errCh <- fmt.Errorf("worker %d iter %d: %w", workerID, j, err)
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
	t.Logf("=== SPRINT 35 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:   %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkWASM_Execution(b *testing.B) {
	engine := NewEngine(DefaultSandboxConfig())
	defer engine.Close()

	code := []byte(`client.chat.completions.create(model="gpt-4o")`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = engine.Execute(context.Background(), LangPython, code, func(ctx context.Context, c []byte) (*ASTNode, []CallSite, error) {
			return &ASTNode{Type: "call"}, nil, nil
		})
	}
}
