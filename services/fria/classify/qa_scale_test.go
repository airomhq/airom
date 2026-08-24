package classify

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_ExtremeClassifyScale_50KSystems(t *testing.T) {
	engine := NewEngine()
	inv := &airom.Inventory{
		Components: []airom.Component{{ID: "c", Kind: airom.KindHostedLLM}},
	}

	const numSystems = 50000
	start := time.Now()

	for i := 0; i < numSystems; i++ {
		domain := "supply_chain"
		if i%4 == 0 {
			domain = "biometric_access"
		} else if i%4 == 1 {
			domain = "hr_recruitment"
		} else if i%4 == 2 {
			domain = "social_scoring"
		}

		res := engine.ClassifySystem(fmt.Sprintf("system-%d", i), domain, inv)
		if res.Tier == "" {
			t.Fatalf("empty tier at iter %d", i)
		}
	}
	duration := time.Since(start)

	systemsPerSec := float64(numSystems) / duration.Seconds()
	t.Logf("=== SPRINT 55 SCALE: 50K EU AI ACT STATUTORY CLASSIFICATIONS ===")
	t.Logf("Systems:    %d", numSystems)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f systems/sec", systemsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentClassifyStorm_100Workers(t *testing.T) {
	engine := NewEngine()

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
				res := engine.ClassifySystem("workforce-ai", "recruitment_hr", nil)
				if res.Tier != TierHighRisk {
					errCh <- fmt.Errorf("unexpected tier: %s", res.Tier)
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
	t.Logf("=== SPRINT 55 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkClassify_ClassifySystem(b *testing.B) {
	engine := NewEngine()
	inv := &airom.Inventory{Components: []airom.Component{{Kind: airom.KindHostedLLM}}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.ClassifySystem("app", "hr_recruitment", inv)
	}
}
