package prober

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeProberScale_50KProbes(t *testing.T) {
	generator := NewGenerator()

	const numProbes = 50000
	start := time.Now()
	probes := generator.GenerateProbes(numProbes)
	duration := time.Since(start)

	if len(probes) != numProbes {
		t.Fatalf("failed scale probe generation")
	}

	probesPerSec := float64(numProbes) / duration.Seconds()
	t.Logf("=== SPRINT 99 SCALE: 50K SYNTHETIC OWASP ATTACK PROBES GENERATED ===")
	t.Logf("Probes:     %d", numProbes)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f probes/sec", probesPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentProberStorm_100Workers(t *testing.T) {
	generator := NewGenerator()

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = generator.GenerateProbes(10)
			}
		}()
	}

	wg.Wait()

	totalOps := numWorkers * iterations * 10
	duration := time.Since(start)
	t.Logf("=== SPRINT 99 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d probes in %v (%.2f probes/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkProber_GenerateProbes(b *testing.B) {
	generator := NewGenerator()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generator.GenerateProbes(100)
	}
}
