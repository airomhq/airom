package dlp

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeDLPScale_100KTokens(t *testing.T) {
	engine := NewEngine(DLPPolicy{DefaultAction: ActionMask})

	// Construct a massive 100,000 token prompt with embedded PII
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString(fmt.Sprintf("User profile %d lives in Colorado. SSN: 123-45-6789. Card: 4532-0150-0000-0049. Token: sk-abcdef1234567890abcdef1234567890. ", i))
	}
	largePayload := b.String()

	start := time.Now()
	res := engine.ScrubText(largePayload)
	duration := time.Since(start)

	if len(res.Findings) != 15000 {
		t.Fatalf("expected 15,000 findings, got %d", len(res.Findings))
	}

	tokensPerSec := float64(res.TokensScanned) / duration.Seconds()
	t.Logf("=== SPRINT 49 SCALE: 100K TOKENS STREAMING DLP REDACTION ===")
	t.Logf("Tokens:     %d", res.TokensScanned)
	t.Logf("Findings:   %d (5K SSNs, 5K Cards, 5K Keys)", len(res.Findings))
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f tokens/sec", tokensPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentDLPStorm_100Workers(t *testing.T) {
	engine := NewEngine(DLPPolicy{DefaultAction: ActionMask})
	input := "Payment info: 4532-0150-0000-0049, SSN: 123-45-6789"

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
				res := engine.ScrubText(input)
				if len(res.Findings) != 2 {
					errCh <- fmt.Errorf("worker %d iter %d expected 2 findings, got %d", workerID, j, len(res.Findings))
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
	t.Logf("=== SPRINT 49 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkDLP_ScrubText(b *testing.B) {
	engine := NewEngine(DLPPolicy{DefaultAction: ActionMask})
	input := "User data: SSN 123-45-6789 and card 4532-0150-0000-0049"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.ScrubText(input)
	}
}
