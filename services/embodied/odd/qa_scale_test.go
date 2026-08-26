package odd

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeODDScale_50KSystems(t *testing.T) {
	evaluator := NewEvaluator()

	const numSystems = 50000
	systems := make([]ODDSpecification, numSystems)
	for i := 0; i < numSystems; i++ {
		systems[i] = ODDSpecification{
			SystemID:            fmt.Sprintf("system_%d", i),
			MaxOperationalSpeed: 30.0,
			AllowedWeathers:     []WeatherCondition{WeatherClear},
			SensorRedundancy:    true,
			FallbackManeuver:    FallbackSafeStop,
			HasSOTIFAssessment:  true,
		}
	}

	start := time.Now()
	for i := 0; i < numSystems; i++ {
		res := evaluator.EvaluateODD(systems[i])
		if !res.IsConformant {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	systemsPerSec := float64(numSystems) / duration.Seconds()
	t.Logf("=== SPRINT 93 SCALE: 50K AUTONOMOUS ODD BOUNDARY PROFILES EVALUATED ===")
	t.Logf("Systems:    %d", numSystems)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f systems/sec", systemsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentODDStorm_100Workers(t *testing.T) {
	evaluator := NewEvaluator()
	spec := ODDSpecification{
		SystemID:           "conc_system",
		SensorRedundancy:   true,
		FallbackManeuver:   FallbackSafeStop,
		HasSOTIFAssessment: true,
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
				res := evaluator.EvaluateODD(spec)
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
	t.Logf("=== SPRINT 93 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkODD_EvaluateODD(b *testing.B) {
	evaluator := NewEvaluator()
	spec := ODDSpecification{
		SystemID:           "bench_system",
		SensorRedundancy:   true,
		FallbackManeuver:   FallbackSafeStop,
		HasSOTIFAssessment: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = evaluator.EvaluateODD(spec)
	}
}
