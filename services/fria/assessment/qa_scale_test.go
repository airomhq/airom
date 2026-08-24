package assessment

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeFRIAScale_10KAssessments(t *testing.T) {
	evaluator := NewEvaluator()

	const numReports = 10000
	start := time.Now()

	for i := 0; i < numReports; i++ {
		report := evaluator.ConductFRIA(
			fmt.Sprintf("AI-System-%d", i),
			"Deployer-Org",
			"Automated decisions",
			[]string{"EU Citizens"},
			"Human-in-the-loop",
		)
		if len(report.RightsAssessed) != 6 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	reportsPerSec := float64(numReports) / duration.Seconds()
	t.Logf("=== SPRINT 56 SCALE: 10K EU AI ACT FRIA STATUTORY ASSESSMENTS ===")
	t.Logf("Assessments: %d", numReports)
	t.Logf("Latency:     %v", duration)
	t.Logf("Throughput:  %.2f assessments/sec", reportsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentFRIAStorm_100Workers(t *testing.T) {
	evaluator := NewEvaluator()

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
				rep := evaluator.ConductFRIA("system", "org", "purpose", []string{"persons"}, "human")
				if rep.StatutoryVerdict != "APPROVED_FOR_DEPLOYMENT" {
					errCh <- fmt.Errorf("unexpected verdict: %s", rep.StatutoryVerdict)
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
	t.Logf("=== SPRINT 56 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkFRIA_ConductFRIA(b *testing.B) {
	evaluator := NewEvaluator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = evaluator.ConductFRIA("system", "org", "purpose", []string{"persons"}, "human")
	}
}
