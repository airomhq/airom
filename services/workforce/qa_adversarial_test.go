package workforce

import (
	"strings"
	"testing"
	"time"
)

func TestQA_AdversarialWorkforceFuzzing(t *testing.T) {
	engine := NewWorkforceEngine()

	// 1. Missing Organization ID
	_, err := engine.AssessWorkforceImpact("", "System", nil, nil, time.Now().UTC())
	if err == nil {
		t.Error("expected error when organization_id is empty")
	}

	// 2. Negative headcounts & zero tasks
	roles := []RoleProfile{
		{
			RoleID:    "neg_role",
			Title:     "Specialist",
			Category:  RoleCategoryEngineering,
			Headcount: -50,        // Adversarial negative headcount
			CoreTasks: []string{}, // Zero tasks
		},
	}
	capabilities := []AISystemCapability{
		{
			Name:           "Bot",
			AutomatedTasks: []string{"task"},
			AutonomyLevel:  -2.5, // Extreme negative autonomy
		},
	}

	report, err := engine.AssessWorkforceImpact("org_fuzz", "System-Fuzz", capabilities, roles, time.Now().UTC())
	if err != nil {
		t.Fatalf("expected graceful handling of negative headcounts, got error: %v", err)
	}
	if report.TotalHeadcount != 0 {
		t.Errorf("expected negative headcount to clamp to 0, got %d", report.TotalHeadcount)
	}
	if report.AggregateDisplacedFTE != 0.0 {
		t.Errorf("expected 0 displaced FTE for 0 headcount, got %.2f", report.AggregateDisplacedFTE)
	}
}

func TestQA_AdversarialDutyOfCareStatutoryCompliance(t *testing.T) {
	engine := NewWorkforceEngine()

	capabilities := []AISystemCapability{
		{
			Name:                "High-Stakes Decision Engine",
			AutomatedTasks:      []string{"hiring-decision", "compensation-scoring"},
			AutonomyLevel:       1.0,
			HighImpactDecisions: true, // Consequential decisioning
		},
	}

	roles := []RoleProfile{
		{
			RoleID:     "hr_lead",
			Title:      "HR Manager",
			Category:   RoleCategoryHR,
			Department: "Human Resources",
			Headcount:  10,
			CoreTasks:  []string{"hiring-decision", "compensation-scoring"},
		},
	}

	report, err := engine.AssessWorkforceImpact("org_statutory_audit", "Consequential-AI", capabilities, roles, time.Now().UTC())
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	if len(report.DutyOfCareNotices) == 0 {
		t.Fatal("expected statutory duty-of-care notices for consequential decision system")
	}

	for _, notice := range report.DutyOfCareNotices {
		if !strings.Contains(notice.Statute, "CO SB 24-205") || !strings.Contains(notice.Statute, "NYC LL144") {
			t.Errorf("notice %s missing statutory citations: %s", notice.NoticeID, notice.Statute)
		}
		if !notice.OptOutAvailable {
			t.Errorf("notice %s must statutory provide opt-out availability", notice.NoticeID)
		}
		if notice.DisputeContactEmail == "" {
			t.Errorf("notice %s must provide employee dispute contact email", notice.NoticeID)
		}
	}
}
