package bidirectional

import (
	"testing"
	"time"
)

func TestITSM_FullLifecycleAutoClose(t *testing.T) {
	coordinator := NewCoordinator()

	// 1. Gap detected -> Creates Ticket
	ticket := coordinator.OnGapDetected(PlatformJira, "repo-core", "EU-AI-ACT-ART-10", "HIGH", "Missing dataset lineage")
	if ticket == nil || ticket.Status != StatusOpen {
		t.Fatalf("expected open ticket, got: %+v", ticket)
	}

	// 2. Query ticket
	retrieved, exists := coordinator.GetTicket("repo-core", "EU-AI-ACT-ART-10")
	if !exists || retrieved.ID != ticket.ID {
		t.Fatalf("failed to retrieve ticket by repo and control")
	}

	// 3. Gap resolved -> Auto-closed
	closedTicket, resolved := coordinator.OnGapResolved("repo-core", "EU-AI-ACT-ART-10")
	if !resolved || closedTicket.Status != StatusAutoClosed || !closedTicket.AutoResolution {
		t.Fatalf("expected auto-closed ticket, got: %+v", closedTicket)
	}
}

func TestITSM_InboundWebhookSync(t *testing.T) {
	coordinator := NewCoordinator()
	ticket := coordinator.OnGapDetected(PlatformServiceNow, "repo-ai", "CO-SB24-205", "CRITICAL", "Impact assessment missing")

	// Inbound webhook from ServiceNow setting status to IN_PROGRESS
	event := InboundWebhookEvent{
		EventID:     "evt-123",
		Platform:    PlatformServiceNow,
		ExternalKey: ticket.ExternalKey,
		NewStatus:   StatusInProgress,
		Timestamp:   time.Now().UTC(),
	}

	updated, err := coordinator.HandleInboundWebhook(event)
	if err != nil || updated.Status != StatusInProgress {
		t.Fatalf("failed inbound webhook handling: %v", err)
	}
}
