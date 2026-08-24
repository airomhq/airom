package assessment

import (
	"strings"
	"testing"
)

func TestFRIA_FullStatutoryAssessment(t *testing.T) {
	evaluator := NewEvaluator()

	report := evaluator.ConductFRIA(
		"Enterprise Loan Decision Engine",
		"EuroBank Group",
		"Automated mortgage underwriting and credit risk evaluation",
		[]string{"Loan applicants in EU member states", "Retail banking consumers"},
		"Human-in-the-loop loan officer sign-off before adverse action",
	)

	if report.StatutoryVerdict != "APPROVED_FOR_DEPLOYMENT" {
		t.Errorf("expected approved verdict, got %s", report.StatutoryVerdict)
	}

	if len(report.RightsAssessed) != 6 {
		t.Errorf("expected 6 fundamental rights evaluated, got %d", len(report.RightsAssessed))
	}
}

func TestFRIA_MissingHumanOversight(t *testing.T) {
	evaluator := NewEvaluator()

	report := evaluator.ConductFRIA(
		"Autonomous Resume Filter",
		"Global Tech Corp",
		"Candidate ranking",
		[]string{"Job applicants"},
		"none", // Missing human oversight
	)

	if !strings.Contains(report.StatutoryVerdict, "MITIGATION_REQUIRED") {
		t.Errorf("expected mitigation required for missing human oversight, got %s", report.StatutoryVerdict)
	}
}
