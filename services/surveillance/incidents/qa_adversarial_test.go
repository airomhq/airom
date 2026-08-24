package incidents

import (
	"testing"
	"time"
)

func TestQA_AdversarialZeroOccurredTime(t *testing.T) {
	engine := NewTriageEngine()

	pkg := engine.TriageIncident(AIIncidentInput{
		IncidentID: "zero-time",
		Severity:   SeverityDeathOrPhysicalHarm,
		OccurredAt: time.Time{}, // Zero time
	})

	if pkg.MandatoryDeadline.IsZero() {
		t.Errorf("expected non-zero deadline using fallback timestamp")
	}
}

func TestQA_AdversarialUnknownSeverity(t *testing.T) {
	engine := NewTriageEngine()

	pkg := engine.TriageIncident(AIIncidentInput{
		IncidentID: "unknown-sev",
		Severity:   "UNKNOWN_SEVERITY_TIER",
	})

	if pkg.NotificationWindow != "15_DAYS" {
		t.Errorf("expected safe fallback to 15_DAYS window")
	}
}
