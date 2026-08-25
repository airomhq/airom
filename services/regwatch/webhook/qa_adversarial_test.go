package webhook

import (
	"testing"
)

func TestQA_AdversarialCaseInsensitiveStateFilters(t *testing.T) {
	dispatcher := NewDispatcher()
	dispatcher.RegisterSubscriber(SubscriberWebhook{
		SubscriberID:     "sub-case",
		SecretKey:        "key",
		SubscribedStates: []string{"cALiFoRNia"},
	})

	event := BillProgressionEvent{
		BillID:       "CA-SB1047",
		Jurisdiction: "CALIFORNIA",
	}

	deliveries := dispatcher.DispatchBillEvent(event)
	if len(deliveries) != 1 {
		t.Fatalf("expected case-insensitive state match")
	}
}

func TestQA_AdversarialEmptyBillEvent(t *testing.T) {
	dispatcher := NewDispatcher()
	dispatcher.RegisterSubscriber(SubscriberWebhook{SubscriberID: "sub-1", SecretKey: "key", SubscribedStates: []string{"ALL"}})

	event := BillProgressionEvent{}
	deliveries := dispatcher.DispatchBillEvent(event)
	if len(deliveries) != 1 {
		t.Fatalf("expected delivery generated on empty bill event")
	}
}
