package watermark

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeWatermarkScale_50KTokens(t *testing.T) {
	cfg := DefaultWatermarkConfig("benchmark-key")
	detector := NewDetector(cfg)

	// 50,000 token payload
	var b strings.Builder
	for i := 0; i < 50000; i++ {
		b.WriteString(fmt.Sprintf("token_%d ", i))
	}
	payload := b.String()

	start := time.Now()
	res := detector.Detect(payload)
	duration := time.Since(start)

	if res.TotalTokens != 50000 {
		t.Fatalf("expected 50,000 tokens, got %d", res.TotalTokens)
	}

	tokensPerSec := float64(res.TotalTokens) / duration.Seconds()
	t.Logf("=== SPRINT 50 SCALE: 50K TOKENS WATERMARK STATISTICAL DETECTION ===")
	t.Logf("Tokens:     %d", res.TotalTokens)
	t.Logf("Z-Score:    %f", res.ZScore)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f tokens/sec", tokensPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentWatermarkStorm_100Workers(t *testing.T) {
	cfg := DefaultWatermarkConfig("conc-key")
	detector := NewDetector(cfg)
	text := "the quick brown fox jumps over the lazy dog and tests watermark verification"

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
				res := detector.Detect(text)
				if res.TotalTokens == 0 {
					errCh <- fmt.Errorf("unexpected empty result")
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
	t.Logf("=== SPRINT 50 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkWatermark_Detect(b *testing.B) {
	cfg := DefaultWatermarkConfig("bench-key")
	detector := NewDetector(cfg)
	text := "a generated synthetic paragraph tested against statistical greenlist presence"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.Detect(text)
	}
}
