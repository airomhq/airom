package treesitter

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/wasm"
)

func TestQA_ExtremeSystemsScale_50KFiles(t *testing.T) {
	goP := NewGoParser()
	rustP := NewRustParser()
	javaP := NewJavaParser()

	const numFiles = 50000
	goCode := []byte(`req := openai.ChatCompletionRequest{Model: "gpt-4o"}`)
	rustCode := []byte(`let req = CreateChatCompletionRequestArgs::default().model("claude-3-5").build()?;`)
	javaCode := []byte(`OpenAiChatModel.builder().modelName("gpt-4o-mini").build();`)

	start := time.Now()
	for i := 0; i < numFiles; i++ {
		switch i % 3 {
		case 0:
			_, calls, err := goP.Parse(goCode)
			if err != nil || len(calls) == 0 {
				t.Fatalf("go fail at %d", i)
			}
		case 1:
			_, calls, err := rustP.Parse(rustCode)
			if err != nil || len(calls) == 0 {
				t.Fatalf("rust fail at %d", i)
			}
		case 2:
			_, calls, err := javaP.Parse(javaCode)
			if err != nil || len(calls) == 0 {
				t.Fatalf("java fail at %d", i)
			}
		}
	}
	duration := time.Since(start)

	fps := float64(numFiles) / duration.Seconds()
	t.Logf("=== SPRINT 37 SCALE: 50K GO/RUST/JAVA FILES PARSED ===")
	t.Logf("Files:      %d", numFiles)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f files/sec", fps)

	if duration > 2*time.Second {
		t.Errorf("expected < 2s, took %v", duration)
	}
}

func TestQA_ConcurrentSystemsStorm_100Workers(t *testing.T) {
	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			var lang wasm.Language
			var code []byte
			switch workerID % 3 {
			case 0:
				lang = wasm.LangGo
				code = []byte(`openai.ChatCompletionRequest{Model: "gpt-4o"}`)
			case 1:
				lang = wasm.LangRust
				code = []byte(`.model("claude-3-5")`)
			case 2:
				lang = wasm.LangJava
				code = []byte(`.modelName("gpt-4o-mini")`)
			}

			parser := SystemsParserFactory(lang)
			for j := 0; j < iterations; j++ {
				_, calls, err := parser.Parse(code)
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
	t.Logf("=== SPRINT 37 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkSystems_GoRustJava(b *testing.B) {
	parser := NewGoParser()
	code := []byte(`req := openai.ChatCompletionRequest{Model: "gpt-4o"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = parser.Parse(code)
	}
}
