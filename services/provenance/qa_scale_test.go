package provenance

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestQA_ExtremeProvenanceScale_10KModels stress-tests provenance graph operations across 10,000 model nodes.
func TestQA_ExtremeProvenanceScale_10KModels(t *testing.T) {
	const modelCount = 10_000
	t.Logf("=== Starting Extreme Scale Provenance Test: %d Models ===", modelCount)

	engine := NewProvenanceEngine(nil)

	// Pre-generate 10,000 models with multi-generational lineage
	nodes := make([]ModelProvenanceNode, modelCount)
	for i := 0; i < modelCount; i++ {
		var baseID string
		if i > 0 && i%10 != 0 {
			baseID = fmt.Sprintf("model_node_%05d", (i/10)*10)
		}

		nodes[i] = ModelProvenanceNode{
			ModelID:            fmt.Sprintf("model_node_%05d", i),
			ModelName:          fmt.Sprintf("Enterprise Model %d", i),
			Version:            fmt.Sprintf("1.%d.0", i%5),
			BaseModelID:        baseID,
			Author:             "AI Engineer",
			Organization:       "Enterprise Corp",
			License:            "Apache-2.0",
			Quantization:       QuantGGUFQ4KM,
			WeightsSHA256:      fmt.Sprintf("weights_sha_%05d_019283746501928374650192837465", i),
			TrainingDatasetIDs: []string{fmt.Sprintf("ds_%d", i%20)},
			TrainingCommitSHA:  "commit_1234567890",
			CreatedTimestamp:   time.Now().UTC(),
		}
	}

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()

	// Register all 10,000 models
	for i := 0; i < modelCount; i++ {
		_, err := engine.RegisterModel(nodes[i])
		if err != nil {
			t.Fatalf("failed to register model %d: %v", i, err)
		}
	}

	// Verify all 10,000 models
	for i := 0; i < modelCount; i++ {
		res, err := engine.VerifyModelProvenance(nodes[i].ModelID, nodes[i].WeightsSHA256)
		if err != nil || !res.Verified {
			t.Fatalf("failed to verify model %d: %v, issues: %v", i, err, res.Issues)
		}
	}

	duration := time.Since(start)
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	modelsPerSec := float64(modelCount*2) / duration.Seconds() // Register + verify

	t.Logf("=== Scale Provenance Results ===")
	t.Logf("Models Processed (Reg+Verify): %d", modelCount*2)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f ops/sec", modelsPerSec)
	t.Logf("Heap Alloc Delta: %.2f KB", float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/1024.0)

	if duration >= 5*time.Second {
		t.Fatalf("Performance violation: 10K model registration & verification took %v (threshold: < 5.0s)", duration)
	}
}

// TestQA_ConcurrentProvenanceStorm_100Workers tests concurrent model registrations with 100 goroutines.
func TestQA_ConcurrentProvenanceStorm_100Workers(t *testing.T) {
	const numWorkers = 100
	const modelsPerWorker = 50
	const totalModels = numWorkers * modelsPerWorker // 5,000 models

	t.Logf("=== Starting Concurrent Provenance Test: %d Workers, %d Total Models ===", numWorkers, totalModels)

	engine := NewProvenanceEngine(nil)

	var (
		completedCount int64
		failedCount    int64
		wg             sync.WaitGroup
	)

	start := time.Now()

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < modelsPerWorker; i++ {
				node := ModelProvenanceNode{
					ModelID:          fmt.Sprintf("worker_%03d_model_%d", workerID, i),
					ModelName:        fmt.Sprintf("Model %d", i),
					Version:          "1.0.0",
					WeightsSHA256:    fmt.Sprintf("sha_%03d_%d_112233445566778899aabbccddeeff", workerID, i),
					License:          "MIT",
					Quantization:     QuantFP16,
					CreatedTimestamp: time.Now().UTC(),
				}

				reg, err := engine.RegisterModel(node)
				if err != nil || reg == nil || reg.AttestationSignature == "" {
					atomic.AddInt64(&failedCount, 1)
					continue
				}

				ver, err := engine.VerifyModelProvenance(node.ModelID, node.WeightsSHA256)
				if err != nil || ver == nil || !ver.Verified {
					atomic.AddInt64(&failedCount, 1)
				} else {
					atomic.AddInt64(&completedCount, 1)
				}
			}
		}(w)
	}

	wg.Wait()
	duration := time.Since(start)
	throughput := float64(totalModels) / duration.Seconds()

	t.Logf("=== Concurrent Provenance Results ===")
	t.Logf("Models Completed: %d | Failures: %d", completedCount, failedCount)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f models/sec", throughput)

	if failedCount > 0 {
		t.Fatalf("expected 0 provenance failures, got %d", failedCount)
	}
	if completedCount != int64(totalModels) {
		t.Fatalf("expected %d completed models, got %d", totalModels, completedCount)
	}
	if duration >= 10*time.Second {
		t.Fatalf("Performance violation: Concurrent provenance took %v (threshold: < 10.0s)", duration)
	}
}

// BenchmarkScale_ModelRegistration benchmarks single model registration.
func BenchmarkScale_ModelRegistration(b *testing.B) {
	engine := NewProvenanceEngine(nil)
	node := ModelProvenanceNode{
		ModelID:          "bench/model",
		ModelName:        "Benchmark Model",
		Version:          "1.0.0",
		WeightsSHA256:    "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
		License:          "Apache-2.0",
		Quantization:     QuantBF16,
		CreatedTimestamp: time.Now().UTC(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = engine.RegisterModel(node)
	}
}
