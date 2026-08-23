package dashboard

import (
	"testing"
)

func TestQA_AdversarialDashboardEmptyAndOutliers(t *testing.T) {
	engine := NewDashboardEngine()

	// 1. Empty organization list
	matrix, err := engine.CalculateExecutivePosture(nil)
	if err != nil {
		t.Fatalf("expected nil orgs to be handled safely, got: %v", err)
	}
	if matrix.Summary.TotalOrganizations != 0 {
		t.Errorf("expected 0 orgs, got %d", matrix.Summary.TotalOrganizations)
	}

	// 2. Zero components and extreme negative compliance
	adversarialOrgs := []OrganizationRollup{
		{
			OrganizationID:    "org_zero",
			OrganizationName:  "Zero Org",
			TotalComponents:   0,     // Zero division edge case
			ComplianceScore:   -50.0, // Negative score
			CriticalGapsCount: 20,
		},
	}

	matrix, err = engine.CalculateExecutivePosture(adversarialOrgs)
	if err != nil {
		t.Fatalf("failed on zero components org: %v", err)
	}

	if matrix.Summary.OverallPostureGrade != GradeF {
		t.Errorf("expected Grade F for 20 critical gaps, got %s", matrix.Summary.OverallPostureGrade)
	}
}
