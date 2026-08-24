package energy

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeEnergyScale_50KJobs(t *testing.T) {
	profiler := NewProfiler()

	const numJobs = 50000
	spec := TrainingJobSpec{
		ModelName:       "Benchmark-Model",
		ParameterCount:  70.0,
		TokenCount:      1000.0,
		Hardware:        GPU_NVIDIA_H100,
		NumAccelerators: 512,
		PUEFactor:       1.15,
	}

	start := time.Now()
	for i := 0; i < numJobs; i++ {
		res := profiler.ComputeTrainingEnergy(spec)
		if res.TotalKWh <= 0 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	jobsPerSec := float64(numJobs) / duration.Seconds()
	t.Logf("=== SPRINT 59 SCALE: 50K AI ENERGY & FLOPS COMPUTATIONS ===")
	t.Logf("Jobs:       %d", numJobs)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f jobs/sec", jobsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentEnergyStorm_100Workers(t *testing.T) {
	profiler := NewProfiler()
	spec := TrainingJobSpec{
		ModelName:       "Conc-Model",
		ParameterCount:  8.0,
		TokenCount:      500.0,
		Hardware:        GPU_NVIDIA_A100,
		NumAccelerators: 64,
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
				res := profiler.ComputeTrainingEnergy(spec)
				if res.TotalFLOPs <= 0 {
					t.Errorf("unexpected FLOPs")
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
	t.Logf("=== SPRINT 59 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkEnergy_ComputeTrainingEnergy(b *testing.B) {
	profiler := NewProfiler()
	spec := TrainingJobSpec{
		ModelName:       "Bench-Model",
		ParameterCount:  70.0,
		TokenCount:      2000.0,
		Hardware:        GPU_NVIDIA_H100,
		NumAccelerators: 1024,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = profiler.ComputeTrainingEnergy(spec)
	}
}
