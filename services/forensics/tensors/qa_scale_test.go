package tensors

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeTensorScale_50KLayers(t *testing.T) {
	detector := NewDetector()

	const numLayers = 50000
	const weightsPerLayer = 1000

	r := rand.New(rand.NewSource(42))
	baseWeights := make([]float32, weightsPerLayer)
	for i := 0; i < len(baseWeights); i++ {
		baseWeights[i] = float32(r.NormFloat64() * 0.02)
	}

	header := TensorLayerHeader{
		Name:       "layer.weight",
		Format:     FormatSafetensors,
		NumWeights: weightsPerLayer,
	}

	start := time.Now()
	for i := 0; i < numLayers; i++ {
		_, _ = detector.AnalyzeLayerStatistics(header, baseWeights)
	}
	duration := time.Since(start)

	totalWeights := int64(numLayers * weightsPerLayer)
	layersPerSec := float64(numLayers) / duration.Seconds()
	weightsPerSec := float64(totalWeights) / duration.Seconds()

	t.Logf("=== SPRINT 61 SCALE: 50K TENSOR LAYERS (%d WEIGHTS) FORENSIC SCAN ===", totalWeights)
	t.Logf("Layers:      %d", numLayers)
	t.Logf("Total Weights: %d", totalWeights)
	t.Logf("Latency:     %v", duration)
	t.Logf("Layer Rate:  %.2f layers/sec", layersPerSec)
	t.Logf("Weight Rate: %.2f weights/sec", weightsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentTensorStorm_100Workers(t *testing.T) {
	detector := NewDetector()
	weights := make([]float32, 1000)
	for i := 0; i < len(weights); i++ {
		weights[i] = 0.01
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
			header := TensorLayerHeader{Name: fmt.Sprintf("layer_%d", workerID)}
			for j := 0; j < iterations; j++ {
				_, detected := detector.AnalyzeLayerStatistics(header, weights)
				if !detected { // uniform weights should trigger entropy collapse
					errCh <- fmt.Errorf("worker %d iter %d expected detection", workerID, j)
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
	t.Logf("=== SPRINT 61 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:   %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkTensor_AnalyzeLayerStatistics(b *testing.B) {
	detector := NewDetector()
	weights := make([]float32, 1000)
	header := TensorLayerHeader{Name: "bench"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.AnalyzeLayerStatistics(header, weights)
	}
}
