package bidirectional

import (
	"testing"
	"time"
)

func TestQA_AdversarialUnknownKeyWebhook(t *testing.T) {
	coordinator := NewCoordinator()
	event := InboundWebhookEvent{
		EventID:     "evt-fake",
		Platform:    PlatformJira,
		ExternalKey: "NON-EXISTENT-99999",
		NewStatus:   StatusResolved,
		Timestamp:   time.Now().UTC(),
	}

	_, err := coordinator.HandleInboundWebhook(event)
	if err == nil {
		t.Fatalf("expected error on unknown external ticket key")
	}
}

func TestQA_AdversarialDuplicateReopenTransitions(t *testing.T) {
	coordinator := NewCoordinator()
	tk1 := coordinator.OnGapDetected(PlatformJira, "repo-1", "CTRL-1", "HIGH", "Summary")
	tk2 := coordinator.OnGapDetected(PlatformJira, "repo-1", "CTRL-1", "HIGH", "Summary")

	if tk1.ID != tk2.ID {
		t.Errorf("expected idempotent ticket creation for same gap, got IDs %s and %s", tk1.ID, tk2.ID)
	}
}
