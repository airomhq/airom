package sse

import (
	"testing"
)

func TestQA_AdversarialSlowClientBufferOverflow(t *testing.T) {
	// Tiny buffer of 2 messages
	b := NewBroadcaster(2)
	_ = b.Subscribe("slow-client", "org-slow")

	// Publish 100 messages rapidly without reading
	for i := 0; i < 100; i++ {
		msg := b.Publish("org-slow", EventRedTeamAlert, "Attack")
		if msg == nil {
			t.Fatalf("failed publish")
		}
	}
	// Broadcaster should not hang or panic
}

func TestQA_AdversarialPublishToNonExistentOrg(t *testing.T) {
	b := NewBroadcaster(10)
	msg := b.Publish("org-ghost-999", EventScanStarted, "Ghost")
	if msg == nil || msg.OrgID != "org-ghost-999" {
		t.Fatalf("expected valid message returned even if no clients are listening")
	}
}
