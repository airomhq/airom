package treaty

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeTreatyScale_50KModels(t *testing.T) {
	evaluator := NewEvaluator()

	const numModels = 50000
	models := make([]FrontierSafetyCommitments, numModels)
	for i := 0; i < numModels; i++ {
		models[i] = FrontierSafetyCommitments{
			ModelName:                fmt.Sprintf("frontier_model_%d", i),
			EstimatedFLOPs:           1e27,
			HasIndependentRedTeam:    true,
			HasCBRNEvaluation:        true,
			HasCyberOffenseLimits:    true,
			HasEmergencyKillSwitch:   true,
			ResponsibleScalingPolicy: true,
		}
	}

	start := time.Now()
	for i := 0; i < numModels; i++ {
		res := evaluator.EvaluateModel(TreatyBletchleyPark, models[i])
		if !res.IsConformant {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	modelsPerSec := float64(numModels) / duration.Seconds()
	t.Logf("=== SPRINT 103 SCALE: 50K FRONTIER MODELS EVALUATED UNDER GLOBAL TREATIES ===")
	t.Logf("Models:     %d", numModels)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f models/sec", modelsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentTreatyStorm_100Workers(t *testing.T) {
	evaluator := NewEvaluator()
	spec := FrontierSafetyCommitments{
		ModelName:              "conc_model",
		EstimatedFLOPs:         1e24, // Below frontier threshold
		HasEmergencyKillSwitch: true,
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
				res := evaluator.EvaluateModel(TreatyG7Hiroshima, spec)
				if !res.IsConformant {
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
	t.Logf("=== SPRINT 103 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkTreaty_EvaluateModel(b *testing.B) {
	evaluator := NewEvaluator()
	spec := FrontierSafetyCommitments{
		ModelName:              "bench_model",
		EstimatedFLOPs:         1e27,
		HasIndependentRedTeam:  true,
		HasCBRNEvaluation:      true,
		HasEmergencyKillSwitch: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = evaluator.EvaluateModel(TreatyBletchleyPark, spec)
	}
}
