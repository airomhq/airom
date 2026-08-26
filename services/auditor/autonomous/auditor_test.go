package autonomous

import (
	"testing"
	"time"
)

func TestAuditor_RegWatchTriggerCreatesTicket(t *testing.T) {
	auditor := NewAuditor()

	evt := AuditEvent{
		EventID:      "evt-regwatch-1",
		Type:         TriggerRegWatchBill,
		Organization: "org-alpha",
		Repository:   "repo-prod",
		BillID:       "CA-SB1047",
		TriggeredAt:  time.Now().UTC(),
	}

	res := auditor.ProcessAuditEvent(evt)
	if res.GapsIdentified != 1 || res.TicketsCreated != 1 {
		t.Fatalf("expected 1 gap and 1 ticket dispatched on RegWatch event, got %+v", res)
	}
}

func TestAuditor_IdempotentDuplicateDeduplication(t *testing.T) {
	auditor := NewAuditor()

	evt := AuditEvent{
		EventID:    "evt-duplicate",
		Type:       TriggerRegWatchBill,
		Repository: "repo-prod",
	}

	res1 := auditor.ProcessAuditEvent(evt)
	res2 := auditor.ProcessAuditEvent(evt)

	if res1.TicketsCreated != 1 || res2.TicketsCreated != 0 {
		t.Fatalf("expected duplicate event to be deduplicated with 0 tickets created")
	}
}
