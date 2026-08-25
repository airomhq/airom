package cloudstream

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeSIEMScale_100KEvents(t *testing.T) {
	streamer := NewStreamer([]byte("scale-key-secret"), 1000)

	const numEvents = 100000
	start := time.Now()

	for i := 0; i < numEvents; i++ {
		_ = streamer.IngestEvent(DestSplunkHEC, "org-scale", "repo-scale", "SHADOW_AI", SeverityMedium, "Finding", "Details")
	}
	duration := time.Since(start)

	batch := streamer.FlushDestination(DestSplunkHEC)
	if batch == nil || batch.EventCount != numEvents {
		t.Fatalf("expected batch with %d events", numEvents)
	}

	eventsPerSec := float64(numEvents) / duration.Seconds()
	t.Logf("=== SPRINT 81 SCALE: 100K SIEM EVENTS SIGNED & BATCHED ===")
	t.Logf("Events:     %d", numEvents)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f events/sec", eventsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentSIEMStorm_100Workers(t *testing.T) {
	streamer := NewStreamer([]byte("conc-key-secret"), 500)

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
				evt := streamer.IngestEvent(DestDatadogLogs, "org-conc", "repo-conc", "AUDIT_LOG", SeverityInfo, "Audit", "Scan completed")
				if !streamer.VerifyEventSignature(*evt) {
					t.Errorf("worker %d iter %d invalid signature", workerID, j)
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
	t.Logf("=== SPRINT 81 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkSIEM_IngestAndSign(b *testing.B) {
	streamer := NewStreamer([]byte("bench-key-secret"), 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = streamer.IngestEvent(DestSplunkHEC, "org-bench", "repo-bench", "GAP", SeverityHigh, "T", "M")
	}
}
