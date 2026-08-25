package sse

import (
	"testing"
	"time"
)

func TestSSE_PublishAndSubscribe(t *testing.T) {
	b := NewBroadcaster(10)

	c1 := b.Subscribe("client-1", "org-acme")
	c2 := b.Subscribe("client-2", "org-other")
	defer b.Unsubscribe("client-1")
	defer b.Unsubscribe("client-2")

	msg := b.Publish("org-acme", EventScanCompleted, "Scan finished with 0 gaps")

	// c1 should receive msg
	select {
	case received := <-c1.Channel:
		if received.ID != msg.ID || received.Payload != "Scan finished with 0 gaps" {
			t.Errorf("unexpected message received: %+v", received)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("timeout waiting for SSE message")
	}

	// c2 should receive nothing (tenant isolated)
	select {
	case unexpected := <-c2.Channel:
		t.Fatalf("SECURITY VIOLATION: org-other received message for org-acme: %+v", unexpected)
	default:
		// Passed
	}
}

func TestSSE_Unsubscribe(t *testing.T) {
	b := NewBroadcaster(10)
	c := b.Subscribe("client-unsub", "org-1")

	if b.ClientCount() != 1 {
		t.Fatalf("expected 1 client")
	}

	b.Unsubscribe("client-unsub")

	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients after unsubscribe")
	}

	// Channel should be closed
	_, ok := <-c.Channel
	if ok {
		t.Errorf("expected channel to be closed")
	}
}
