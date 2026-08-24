package middleware

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/services/gateway/dlp"
	"github.com/airomhq/airom/services/gateway/watermark"
)

func TestQA_ExtremeMiddlewareScale_10KRequests(t *testing.T) {
	pipeline := NewPipeline(
		dlp.DLPPolicy{DefaultAction: dlp.ActionMask},
		watermark.DefaultWatermarkConfig("benchmark-key"),
	)

	const numReqs = 10000
	req := InterceptRequest{
		SessionID: "scale",
		Model:     "claude-3-5-sonnet",
		Prompt:    "User card 4532-0150-0000-0049. Please process payment.",
	}

	start := time.Now()
	for i := 0; i < numReqs; i++ {
		_, err := pipeline.Intercept(context.Background(), req, func(p string) (string, error) {
			return "Payment processed successfully for customer.", nil
		})
		if err != nil {
			t.Fatalf("failed at iter %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	reqsPerSec := float64(numReqs) / duration.Seconds()
	t.Logf("=== SPRINT 51 SCALE: 10K GATEWAY MIDDLEWARE ROUND-TRIPS ===")
	t.Logf("Requests:   %d", numReqs)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f reqs/sec", reqsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentMiddlewareStorm_100Workers(t *testing.T) {
	pipeline := NewPipeline(
		dlp.DLPPolicy{DefaultAction: dlp.ActionMask},
		watermark.DefaultWatermarkConfig("conc-key"),
	)

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			req := InterceptRequest{
				SessionID: fmt.Sprintf("worker-%d", workerID),
				Model:     "gpt-4o",
				Prompt:    "User SSN is 123-45-6789. Summary.",
			}
			for j := 0; j < iterations; j++ {
				_, err := pipeline.Intercept(context.Background(), req, func(p string) (string, error) {
					return "Summary generated.", nil
				})
				if err != nil {
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
	t.Logf("=== SPRINT 51 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkMiddleware_Intercept(b *testing.B) {
	pipeline := NewPipeline(
		dlp.DLPPolicy{DefaultAction: dlp.ActionMask},
		watermark.DefaultWatermarkConfig("bench-key"),
	)
	req := InterceptRequest{
		SessionID: "b",
		Model:     "gpt-4o",
		Prompt:    "Customer record SSN: 123-45-6789",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pipeline.Intercept(context.Background(), req, func(p string) (string, error) {
			return "OK", nil
		})
	}
}
