package multimodal

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeMultiModalScale_50KPayloads(t *testing.T) {
	prober := NewProber()

	const numPayloads = 50000
	payloads := make([]MultiModalPayload, numPayloads)
	for i := 0; i < numPayloads; i++ {
		payloads[i] = MultiModalPayload{
			PayloadID:     fmt.Sprintf("payload_%d", i),
			MimeType:      "image/png",
			ExtractedText: "Normal visual caption describing a graph diagram",
			RawBytes:      []byte("\x89PNG\r\n\x1a\n"),
		}
	}

	start := time.Now()
	for i := 0; i < numPayloads; i++ {
		verdict := prober.EvaluatePayload(payloads[i])
		if verdict.IsMalicious {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	payloadsPerSec := float64(numPayloads) / duration.Seconds()
	t.Logf("=== SPRINT 97 SCALE: 50K MULTI-MODAL PROMPT INJECTION PAYLOADS SCANNED ===")
	t.Logf("Payloads:   %d", numPayloads)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f payloads/sec", payloadsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentMultiModalStorm_100Workers(t *testing.T) {
	prober := NewProber()
	payload := MultiModalPayload{
		PayloadID:     "conc_payload",
		MimeType:      "image/png",
		ExtractedText: "Benign content",
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
				verdict := prober.EvaluatePayload(payload)
				if verdict.IsMalicious {
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
	t.Logf("=== SPRINT 97 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkMultiModal_EvaluatePayload(b *testing.B) {
	prober := NewProber()
	payload := MultiModalPayload{
		PayloadID:     "bench",
		MimeType:      "image/jpeg",
		ExtractedText: "Normal photo caption",
		RawBytes:      []byte("\xff\xd8\xff\xe0"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = prober.EvaluatePayload(payload)
	}
}
