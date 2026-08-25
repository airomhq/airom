package webhook

import (
	"testing"
	"time"
)

func TestWebhook_DispatchEvent(t *testing.T) {
	dispatcher := NewDispatcher()

	dispatcher.RegisterSubscriber(SubscriberWebhook{
		SubscriberID:     "sub-all",
		TargetURL:        "https://acme.com/webhooks/regwatch",
		SecretKey:        "secret-key-1",
		SubscribedStates: []string{"ALL"},
	})

	dispatcher.RegisterSubscriber(SubscriberWebhook{
		SubscriberID:     "sub-ca-only",
		TargetURL:        "https://acme.com/webhooks/ca-only",
		SecretKey:        "secret-key-2",
		SubscribedStates: []string{"California"},
	})

	dispatcher.RegisterSubscriber(SubscriberWebhook{
		SubscriberID:     "sub-ma-only",
		TargetURL:        "https://acme.com/webhooks/ma-only",
		SecretKey:        "secret-key-3",
		SubscribedStates: []string{"Massachusetts"},
	})

	event := BillProgressionEvent{
		BillID:         "CA-SB1047",
		Jurisdiction:   "California",
		BillTitle:      "Safe and Secure Innovation for Frontier Artificial Intelligence Models Act",
		CurrentStage:   StageFloorVote,
		PreviousStage:  StageCommitteePassed,
		ImpactSeverity: "BREAKING_STATUTORY_SHIFT",
		AdvancedAt:     time.Now().UTC(),
	}

	deliveries := dispatcher.DispatchBillEvent(event)

	// sub-all and sub-ca-only should match; sub-ma-only should be excluded (2 total)
	if len(deliveries) != 2 {
		t.Fatalf("expected 2 matching deliveries, got %d", len(deliveries))
	}

	for _, d := range deliveries {
		if d.Signature == "" || d.AlertID == "" {
			t.Errorf("missing signature or alert ID in outbound payload: %+v", d)
		}
	}
}

func TestWebhook_EmptySubscribers(t *testing.T) {
	dispatcher := NewDispatcher()
	event := BillProgressionEvent{Jurisdiction: "New York"}
	deliveries := dispatcher.DispatchBillEvent(event)
	if len(deliveries) != 0 {
		t.Errorf("expected 0 deliveries on empty subscribers")
	}
}
