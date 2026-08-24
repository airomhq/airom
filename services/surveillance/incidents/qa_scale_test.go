package incidents

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeIncidentScale_50KTriage(t *testing.T) {
	engine := NewTriageEngine()

	const numIncidents = 50000
	now := time.Now().UTC()
	input := AIIncidentInput{
		IncidentID: "scale",
		Severity:   SeverityDeathOrPhysicalHarm,
		OccurredAt: now,
	}

	start := time.Now()
	for i := 0; i < numIncidents; i++ {
		pkg := engine.TriageIncident(input)
		if pkg.NotificationWindow != "72_HOURS" {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	incidentsPerSec := float64(numIncidents) / duration.Seconds()
	t.Logf("=== SPRINT 71 SCALE: 50K STATUTORY INCIDENT TRIAGE RUNS ===")
	t.Logf("Incidents:  %d", numIncidents)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f incidents/sec", incidentsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentIncidentStorm_100Workers(t *testing.T) {
	engine := NewTriageEngine()
	now := time.Now().UTC()

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			input := AIIncidentInput{
				IncidentID: fmt.Sprintf("inc-%d", workerID),
				Severity:   SeverityCriticalInfraDisrupt,
				OccurredAt: now,
			}
			for j := 0; j < iterations; j++ {
				pkg := engine.TriageIncident(input)
				if pkg.NotificationWindow != "15_DAYS" {
					errCh <- fmt.Errorf("unexpected window: %s", pkg.NotificationWindow)
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
	t.Logf("=== SPRINT 71 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkIncidents_TriageIncident(b *testing.B) {
	engine := NewTriageEngine()
	input := AIIncidentInput{Severity: SeverityDeathOrPhysicalHarm, OccurredAt: time.Now().UTC()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.TriageIncident(input)
	}
}
