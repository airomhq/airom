package treesitter

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeTreeSitterScale_50KFiles(t *testing.T) {
	pyParser := NewPythonParser()
	tsParser := NewTypeScriptParser()

	const numFiles = 50000
	pyCode := []byte(`client.chat.completions.create(model="gpt-4o", temperature=0.7)`)
	tsCode := []byte(`const res = await openai.chat({ model: "claude-3-5", temperature: 0.2 });`)

	start := time.Now()
	for i := 0; i < numFiles; i++ {
		if i%2 == 0 {
			_, calls, err := pyParser.Parse(pyCode)
			if err != nil || len(calls) == 0 {
				t.Fatalf("py parse failed at iter %d", i)
			}
		} else {
			_, calls, err := tsParser.Parse(tsCode)
			if err != nil || len(calls) == 0 {
				t.Fatalf("ts parse failed at iter %d", i)
			}
		}
	}
	duration := time.Since(start)

	filesPerSec := float64(numFiles) / duration.Seconds()
	t.Logf("=== SPRINT 36 SCALE: 50K PYTHON & TS FILES PARSED ===")
	t.Logf("Files:      %d", numFiles)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f files/sec", filesPerSec)

	if duration > 2*time.Second {
		t.Errorf("expected execution < 2s, took %v", duration)
	}
}

func TestQA_ConcurrentTreeSitterStorm_100Workers(t *testing.T) {
	pyParser := NewPythonParser()
	const numWorkers = 100
	const iterations = 500
	code := []byte(`pipeline("text-generation", model="meta-llama/Meta-Llama-3-8B-Instruct")`)

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, calls, err := pyParser.Parse(code)
				if err != nil || len(calls) == 0 {
					errCh <- fmt.Errorf("worker %d iter %d parse failed", workerID, j)
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
	t.Logf("=== SPRINT 36 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkTreeSitter_Python(b *testing.B) {
	pyParser := NewPythonParser()
	code := []byte(`response = client.chat.completions.create(model="gpt-4o", temperature=0.7)`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = pyParser.Parse(code)
	}
}
