package hybrid

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/wasm"
)

func TestQA_ExtremeHybridScale_100KFiles(t *testing.T) {
	p := NewPipeline(nil)
	defer p.Close()

	const numFiles = 100000
	nonAICode := []byte(`package utils; func Add(a, b int) int { return a + b }`)
	aiCode := []byte(`client.chat.completions.create(model="gpt-4o", temperature=0.2)`)

	start := time.Now()
	fastPathCount := 0
	astCount := 0

	for i := 0; i < numFiles; i++ {
		var code []byte
		if i%10 == 0 {
			code = aiCode
		} else {
			code = nonAICode
		}

		hasCand, calls, err := p.ScanFile(context.Background(), wasm.LangPython, code)
		if err != nil {
			t.Fatalf("scan failed at iter %d: %v", i, err)
		}

		if hasCand {
			astCount++
			if len(calls) == 0 {
				t.Fatalf("expected calls for AI file %d", i)
			}
		} else {
			fastPathCount++
		}
	}
	duration := time.Since(start)

	fps := float64(numFiles) / duration.Seconds()
	t.Logf("=== SPRINT 38 SCALE: 100K HYBRID SOURCE FILES ===")
	t.Logf("Total Files:     %d", numFiles)
	t.Logf("FastPath Skip:   %d (%.1f%%)", fastPathCount, float64(fastPathCount)/float64(numFiles)*100)
	t.Logf("AST Evaluated:   %d (%.1f%%)", astCount, float64(astCount)/float64(numFiles)*100)
	t.Logf("Latency:         %v", duration)
	t.Logf("Throughput:      %.2f files/sec", fps)

	if duration > 2*time.Second {
		t.Errorf("expected execution < 2s, took %v", duration)
	}
}

func TestQA_ConcurrentHybridStorm_100Workers(t *testing.T) {
	cfg := wasm.DefaultSandboxConfig()
	cfg.TimeoutPerFile = 2 * time.Second
	engine := wasm.NewEngine(cfg)
	p := NewPipeline(engine)
	defer p.Close()

	const numWorkers = 100
	const iterations = 500
	aiCode := []byte(`pipeline("text-generation", model="meta-llama/Meta-Llama-3-8B-Instruct")`)

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				hasCand, calls, err := p.ScanFile(context.Background(), wasm.LangPython, aiCode)
				if err != nil || !hasCand || len(calls) == 0 {
					errCh <- fmt.Errorf("worker %d iter %d failed: err=%v", workerID, j, err)
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
	t.Logf("=== SPRINT 38 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkHybrid_MixedCorpus(b *testing.B) {
	p := NewPipeline(nil)
	defer p.Close()

	nonAICode := []byte(`func ComputeSum(a, b int) int { return a + b }`)
	aiCode := []byte(`client.chat.completions.create(model="gpt-4o")`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%10 == 0 {
			_, _, _ = p.ScanFile(context.Background(), wasm.LangPython, aiCode)
		} else {
			_, _, _ = p.ScanFile(context.Background(), wasm.LangPython, nonAICode)
		}
	}
}
