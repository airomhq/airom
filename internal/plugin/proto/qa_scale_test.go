package proto

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/plugin"
	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_ExtremeProtoScale_50KRequests(t *testing.T) {
	transport := plugin.NewTransport("secret")
	respBytes, _ := json.Marshal(DetectResponse{
		Components: []airom.Component{{ID: "c1", Kind: airom.KindHostedLLM, Name: "model"}},
	})

	transport.RegisterMethod("detector.detect", func(req plugin.PluginMessage) plugin.PluginMessage {
		return plugin.PluginMessage{ID: req.ID, Method: req.Method, Payload: respBytes}
	})

	adapter := NewDetectorAdapter(transport)
	req := DetectRequest{
		SessionID: "bench-s",
		FilePath:  "file.py",
		Content:   []byte("test_content"),
	}

	const numReqs = 50000
	start := time.Now()

	for i := 0; i < numReqs; i++ {
		resp, err := adapter.Detect(context.Background(), req)
		if err != nil || len(resp.Components) != 1 {
			t.Fatalf("failed at iter %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	rps := float64(numReqs) / duration.Seconds()
	t.Logf("=== SPRINT 43 SCALE: 50K PLUGIN PROTO DISPATCHES ===")
	t.Logf("Dispatches: %d", numReqs)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f dispatches/sec", rps)

	if duration > 2*time.Second {
		t.Errorf("expected execution < 2s, took %v", duration)
	}
}

func TestQA_ConcurrentProtoStorm_100Workers(t *testing.T) {
	transport := plugin.NewTransport("secret")
	respBytes, _ := json.Marshal(DetectResponse{
		Components: []airom.Component{{ID: "c1", Kind: airom.KindHostedLLM, Name: "model"}},
	})

	transport.RegisterMethod("detector.detect", func(req plugin.PluginMessage) plugin.PluginMessage {
		return plugin.PluginMessage{ID: req.ID, Method: req.Method, Payload: respBytes}
	})

	adapter := NewDetectorAdapter(transport)
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
				req := DetectRequest{
					SessionID: fmt.Sprintf("%d-%d", workerID, j),
					FilePath:  "file.py",
				}
				resp, err := adapter.Detect(context.Background(), req)
				if err != nil || len(resp.Components) == 0 {
					errCh <- fmt.Errorf("worker %d iter %d failed: %w", workerID, j, err)
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
	t.Logf("=== SPRINT 43 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkProto_DetectorDispatch(b *testing.B) {
	transport := plugin.NewTransport("secret")
	respBytes, _ := json.Marshal(DetectResponse{
		Components: []airom.Component{{ID: "c1", Kind: airom.KindHostedLLM, Name: "model"}},
	})
	transport.RegisterMethod("detector.detect", func(req plugin.PluginMessage) plugin.PluginMessage {
		return plugin.PluginMessage{ID: req.ID, Method: req.Method, Payload: respBytes}
	})

	adapter := NewDetectorAdapter(transport)
	req := DetectRequest{SessionID: "b", FilePath: "file.py"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = adapter.Detect(context.Background(), req)
	}
}
