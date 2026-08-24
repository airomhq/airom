package plugin

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremePluginScale_100KRPC(t *testing.T) {
	transport := NewTransport("secret")
	transport.RegisterMethod("detector.scan", func(req PluginMessage) PluginMessage {
		return PluginMessage{ID: req.ID, Method: "detector.scan", Payload: []byte(`{"findings": 1}`)}
	})

	const numCalls = 100000
	msg := PluginMessage{ID: "req-1", Method: "detector.scan", Payload: []byte("scan_payload")}

	start := time.Now()
	for i := 0; i < numCalls; i++ {
		resp, err := transport.Call(msg)
		if err != nil || resp.IsError {
			t.Fatalf("call failed at %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	rps := float64(numCalls) / duration.Seconds()
	t.Logf("=== SPRINT 42 SCALE: 100K PLUGIN IPC CALLS ===")
	t.Logf("Calls:      %d", numCalls)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f calls/sec", rps)

	if duration > 2*time.Second {
		t.Errorf("expected execution < 2s, took %v", duration)
	}
}

func TestQA_ConcurrentPluginStorm_100Workers(t *testing.T) {
	transport := NewTransport("secret")
	transport.RegisterMethod("detector.scan", func(req PluginMessage) PluginMessage {
		return PluginMessage{ID: req.ID, Method: "detector.scan", Payload: []byte("OK")}
	})

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
				msg := PluginMessage{
					ID:      fmt.Sprintf("%d-%d", workerID, j),
					Method:  "detector.scan",
					Payload: []byte("test"),
				}
				resp, err := transport.Call(msg)
				if err != nil || resp.IsError {
					errCh <- fmt.Errorf("worker %d iter %d call failed: %w", workerID, j, err)
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
	t.Logf("=== SPRINT 42 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkPlugin_Call(b *testing.B) {
	transport := NewTransport("secret")
	transport.RegisterMethod("echo", func(req PluginMessage) PluginMessage {
		return req
	})
	msg := PluginMessage{Method: "echo", Payload: []byte("benchmark")}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = transport.Call(msg)
	}
}
