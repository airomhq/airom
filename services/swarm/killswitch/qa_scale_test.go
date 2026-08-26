package killswitch

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeKillSwitchScale_50KChecks(t *testing.T) {
	mesh := NewMesh()

	const numAgents = 50000
	for i := 0; i < numAgents; i++ {
		mesh.RegisterAgent(fmt.Sprintf("agent_%d", i), "cluster-main")
	}

	start := time.Now()
	for i := 0; i < numAgents; i++ {
		canRun, _ := mesh.CanExecute(fmt.Sprintf("agent_%d", i))
		if !canRun {
			t.Fatalf("failed check at iter %d", i)
		}
	}
	duration := time.Since(start)

	checksPerSec := float64(numAgents) / duration.Seconds()
	t.Logf("=== SPRINT 102 SCALE: 50K DISTRIBUTED KILL-SWITCH CHECKS COMPLETED ===")
	t.Logf("Checks:     %d", numAgents)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f checks/sec", checksPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentKillSwitchStorm_100Workers(t *testing.T) {
	mesh := NewMesh()
	mesh.RegisterAgent("conc_agent", "conc_cluster")

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = mesh.CanExecute("conc_agent")
			}
		}()
	}

	wg.Wait()

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 102 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkKillSwitch_CanExecute(b *testing.B) {
	mesh := NewMesh()
	mesh.RegisterAgent("bench_agent", "cluster")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mesh.CanExecute("bench_agent")
	}
}
