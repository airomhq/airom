package autonomous

import (
	"testing"
)

func TestQA_AdversarialEmptyEvent(t *testing.T) {
	auditor := NewAuditor()

	res := auditor.ProcessAuditEvent(AuditEvent{})
	if res.RunID == "" {
		t.Fatalf("expected valid run ID generated on empty event")
	}
}

func TestQA_AdversarialUnknownTrigger(t *testing.T) {
	auditor := NewAuditor()

	res := auditor.ProcessAuditEvent(AuditEvent{
		Type: TriggerType("CORRUPTED_TRIGGER_TYPE"),
	})
	if res.GapsIdentified != 0 {
		t.Fatalf("expected 0 gaps on unknown trigger")
	}
}
