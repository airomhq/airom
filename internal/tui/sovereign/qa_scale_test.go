package sovereign

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeTUIScale_50KFrames(t *testing.T) {
	renderer := NewRenderer()
	state := TerminalState{
		ActiveView:      ViewDashboard,
		SystemName:      "Scale-System",
		ComplianceScore: 100.0,
		RenderedAt:      time.Now().UTC(),
	}

	const numFrames = 50000
	start := time.Now()

	for i := 0; i < numFrames; i++ {
		frame := renderer.RenderFrame(state, 80, 24)
		if len(frame) == 0 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	framesPerSec := float64(numFrames) / duration.Seconds()
	t.Logf("=== SPRINT 74 SCALE: 50K SOVEREIGN TUI TERMINAL FRAME RENDERS ===")
	t.Logf("Frames:     %d", numFrames)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f frames/sec", framesPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentTUIStorm_100Workers(t *testing.T) {
	renderer := NewRenderer()
	state := TerminalState{ActiveView: ViewDashboard, SystemName: "Conc", RenderedAt: time.Now().UTC()}

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
				frame := renderer.RenderFrame(state, 80, 24)
				if len(frame) == 0 {
					t.Errorf("empty frame")
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
	t.Logf("=== SPRINT 74 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkTUI_RenderFrame(b *testing.B) {
	renderer := NewRenderer()
	state := TerminalState{ActiveView: ViewDashboard, SystemName: "Bench", RenderedAt: time.Now().UTC()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = renderer.RenderFrame(state, 80, 24)
	}
}
