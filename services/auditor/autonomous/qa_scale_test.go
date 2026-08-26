package autonomous

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeAuditorScale_50KEvents(t *testing.T) {
	auditor := NewAuditor()

	const numEvents = 50000
	events := make([]AuditEvent, numEvents)
	for i := 0; i < numEvents; i++ {
		events[i] = AuditEvent{
			EventID:    fmt.Sprintf("evt_%d", i),
			Type:       TriggerRegWatchBill,
			Repository: fmt.Sprintf("repo_%d", i),
		}
	}

	start := time.Now()
	for i := 0; i < numEvents; i++ {
		res := auditor.ProcessAuditEvent(events[i])
		if res.TicketsCreated != 1 {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	eventsPerSec := float64(numEvents) / duration.Seconds()
	t.Logf("=== SPRINT 104 SCALE: 50K CONTINUOUS AUTONOMOUS AUDIT RUNS COMPLETED ===")
	t.Logf("Events:     %d", numEvents)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f events/sec", eventsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentAuditorStorm_100Workers(t *testing.T) {
	auditor := NewAuditor()

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				evt := AuditEvent{
					EventID:    fmt.Sprintf("w_%d_j_%d", workerID, j),
					Type:       TriggerContinuousJob,
					Repository: "repo",
				}
				_ = auditor.ProcessAuditEvent(evt)
			}
		}(i)
	}

	wg.Wait()

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 104 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkAuditor_ProcessAuditEvent(b *testing.B) {
	auditor := NewAuditor()
	evt := AuditEvent{
		EventID:    "bench_evt",
		Type:       TriggerContinuousJob,
		Repository: "repo",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auditor.ProcessAuditEvent(evt)
	}
}
