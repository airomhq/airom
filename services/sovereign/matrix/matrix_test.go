package matrix

import (
	"testing"
)

func TestMatrix_GlobalPass_MinimalRisk(t *testing.T) {
	harmonizer := NewHarmonizer()

	res := harmonizer.Harmonize("Supply Chain Optimizer", "logistics_inventory", nil)
	if res.OverallVerdict != "GLOBAL_PASS" {
		t.Errorf("expected GLOBAL_PASS for minimal risk, got %s", res.OverallVerdict)
	}

	if res.CompliantCount != 6 {
		t.Errorf("expected 6/6 compliant frameworks, got %d", res.CompliantCount)
	}
}

func TestMatrix_RegionalRestrictions_HighRiskHR(t *testing.T) {
	harmonizer := NewHarmonizer()

	res := harmonizer.Harmonize("Talent AI", "recruitment_hr", nil)
	if res.OverallVerdict != "REGIONAL_RESTRICTIONS" {
		t.Errorf("expected REGIONAL_RESTRICTIONS for HR AI, got %s", res.OverallVerdict)
	}

	euVerdict := res.Verdicts[FrameworkEU_AI_Act]
	if euVerdict.Status != "GAP_IDENTIFIED" || len(euVerdict.RequiredFilings) < 3 {
		t.Errorf("expected EU AI Act gap with mandatory filings: %+v", euVerdict)
	}
}

func TestMatrix_ProhibitedSystem_SocialScoring(t *testing.T) {
	harmonizer := NewHarmonizer()

	res := harmonizer.Harmonize("Citizen Behavior Engine", "social_scoring", nil)
	if res.OverallVerdict != "PROHIBITED" {
		t.Errorf("expected PROHIBITED for social scoring, got %s", res.OverallVerdict)
	}
}
