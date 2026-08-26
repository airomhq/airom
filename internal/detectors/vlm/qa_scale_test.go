package vlm

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeVLMScale_50KPipelines(t *testing.T) {
	detector := NewDetector()

	const numPipelines = 50000
	pipelines := make([]InferenceSpec, numPipelines)
	for i := 0; i < numPipelines; i++ {
		pipelines[i] = InferenceSpec{
			Framework:           FrameworkWhisper,
			ModelID:             fmt.Sprintf("openai/whisper-%d", i),
			MaxAudioDurationSec: 60,
		}
	}

	start := time.Now()
	for i := 0; i < numPipelines; i++ {
		res := detector.EvaluateInference(pipelines[i])
		if !res.IsSafe {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	pipesPerSec := float64(numPipelines) / duration.Seconds()
	t.Logf("=== SPRINT 108 SCALE: 50K VLM & AUDIO INFERENCE PIPELINES EVALUATED ===")
	t.Logf("Pipelines:  %d", numPipelines)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f pipelines/sec", pipesPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentVLMStorm_100Workers(t *testing.T) {
	detector := NewDetector()
	spec := InferenceSpec{
		Framework:      FrameworkPixtral,
		ModelID:        "conc_pixtral",
		MaxImagePixels: 2 * 1024 * 1024,
		HasPromptGuard: true,
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
				res := detector.EvaluateInference(spec)
				if !res.IsSafe {
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
	t.Logf("=== SPRINT 108 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkVLM_EvaluateInference(b *testing.B) {
	detector := NewDetector()
	spec := InferenceSpec{
		Framework:      FrameworkPixtral,
		ModelID:        "bench_pixtral",
		MaxImagePixels: 2 * 1024 * 1024,
		HasPromptGuard: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.EvaluateInference(spec)
	}
}
