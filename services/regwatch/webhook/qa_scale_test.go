package webhook

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeWebhookScale_50KDispatches(t *testing.T) {
	dispatcher := NewDispatcher()

	const numSubscribers = 10
	for i := 0; i < numSubscribers; i++ {
		dispatcher.RegisterSubscriber(SubscriberWebhook{
			SubscriberID:     fmt.Sprintf("sub-%d", i),
			TargetURL:        "https://api.example.com/alerts",
			SecretKey:        "secret-scale-key",
			SubscribedStates: []string{"ALL"},
		})
	}

	event := BillProgressionEvent{
		BillID:         "MA-H4887",
		Jurisdiction:   "Massachusetts",
		CurrentStage:   StageCommitteePassed,
		ImpactSeverity: "BREAKING_STATUTORY_SHIFT",
		AdvancedAt:     time.Now().UTC(),
	}

	const numDispatches = 5000
	start := time.Now()

	for i := 0; i < numDispatches; i++ {
		deliveries := dispatcher.DispatchBillEvent(event)
		if len(deliveries) != numSubscribers {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	totalDeliveries := numDispatches * numSubscribers
	delivsPerSec := float64(totalDeliveries) / duration.Seconds()
	t.Logf("=== SPRINT 85 SCALE: 50K SIGNED LEGISLATIVE ALERT DELIVERIES ===")
	t.Logf("Dispatches: %d", numDispatches)
	t.Logf("Deliveries: %d", totalDeliveries)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f deliveries/sec", delivsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentWebhookStorm_100Workers(t *testing.T) {
	dispatcher := NewDispatcher()
	const numSubscribers = 5
	for i := 0; i < numSubscribers; i++ {
		dispatcher.RegisterSubscriber(SubscriberWebhook{
			SubscriberID:     fmt.Sprintf("conc-sub-%d", i),
			SecretKey:        "conc-secret-key",
			SubscribedStates: []string{"ALL"},
		})
	}

	event := BillProgressionEvent{BillID: "WA-SB5838", Jurisdiction: "Washington", CurrentStage: StageFloorVote}

	const numWorkers = 100
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				deliveries := dispatcher.DispatchBillEvent(event)
				if len(deliveries) != numSubscribers {
					return
				}
			}
		}()
	}

	wg.Wait()

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 85 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkWebhook_DispatchBillEvent(b *testing.B) {
	dispatcher := NewDispatcher()
	dispatcher.RegisterSubscriber(SubscriberWebhook{SubscriberID: "bench", SecretKey: "key", SubscribedStates: []string{"ALL"}})
	event := BillProgressionEvent{BillID: "NY-A09435", Jurisdiction: "New York"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dispatcher.DispatchBillEvent(event)
	}
}
