package incidents

import (
	"testing"
	"time"
)

func TestIncidents_72HourMandatoryDeathHarm(t *testing.T) {
	engine := NewTriageEngine()

	now := time.Now().UTC()
	input := AIIncidentInput{
		IncidentID:          "inc-001",
		SystemName:          "Autonomous Medical Diagnostics",
		Provider:            "HealthAI Inc",
		Severity:            SeverityDeathOrPhysicalHarm,
		AffectedIndividuals: 3,
		HarmDescription:     "Severe adverse diagnostic misclassification",
		OccurredAt:          now,
	}

	pkg := engine.TriageIncident(input)
	if pkg.NotificationWindow != "72_HOURS" {
		t.Errorf("expected 72_HOURS notification window, got %s", pkg.NotificationWindow)
	}

	expectedDeadline := now.Add(72 * time.Hour)
	if !pkg.MandatoryDeadline.Equal(expectedDeadline) {
		t.Errorf("expected deadline %v, got %v", expectedDeadline, pkg.MandatoryDeadline)
	}

	if len(pkg.TargetAuthorities) < 3 {
		t.Errorf("expected at least 3 target authorities, got %d", len(pkg.TargetAuthorities))
	}
}

func TestIncidents_ColoradoAlgorithmicBias(t *testing.T) {
	engine := NewTriageEngine()

	now := time.Now().UTC()
	input := AIIncidentInput{
		IncidentID:          "inc-002",
		SystemName:          "Talent Screener",
		Provider:            "WorkForce Corp",
		Severity:            SeverityAlgorithmicBias,
		AffectedIndividuals: 50,
		HarmDescription:     "Disparate impact detected in hiring screening",
		OccurredAt:          now,
	}

	pkg := engine.TriageIncident(input)
	if pkg.NotificationWindow != "90_DAYS" {
		t.Errorf("expected 90_DAYS window for Colorado algorithmic bias, got %s", pkg.NotificationWindow)
	}

	expectedDeadline := now.Add(90 * 24 * time.Hour)
	if !pkg.MandatoryDeadline.Equal(expectedDeadline) {
		t.Errorf("expected deadline %v, got %v", expectedDeadline, pkg.MandatoryDeadline)
	}
}
