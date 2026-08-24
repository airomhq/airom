package stego

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeStegoScale_50KLayers(t *testing.T) {
	extractor := NewExtractor()

	carrier := make([]byte, 512)
	for i := range carrier {
		carrier[i] = byte(i % 256)
	}

	const numLayers = 50000
	start := time.Now()

	for i := 0; i < numLayers; i++ {
		_, _ = extractor.ExtractLSBBytes("layer.weight", carrier)
	}
	duration := time.Since(start)

	layersPerSec := float64(numLayers) / duration.Seconds()
	t.Logf("=== SPRINT 62 SCALE: 50K TENSOR STEGANOGRAPHY SCANS ===")
	t.Logf("Layers:     %d", numLayers)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f layers/sec", layersPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentStegoStorm_100Workers(t *testing.T) {
	extractor := NewExtractor()
	carrier := make([]byte, 512)
	for i := range carrier {
		carrier[i] = byte(i % 256)
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
				_, _ = extractor.ExtractLSBBytes("layer.weight", carrier)
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
	t.Logf("=== SPRINT 62 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkStego_ExtractLSBBytes(b *testing.B) {
	extractor := NewExtractor()
	carrier := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extractor.ExtractLSBBytes("bench", carrier)
	}
}
