package assessment

import (
	"strings"
	"testing"
)

func TestQA_AdversarialEmptyStringsAndSlices(t *testing.T) {
	evaluator := NewEvaluator()

	report := evaluator.ConductFRIA("", "", "", nil, "")
	if len(report.RightsAssessed) != 6 {
		t.Errorf("expected 6 rights assessed even on empty inputs")
	}
	if !strings.Contains(report.StatutoryVerdict, "MITIGATION_REQUIRED") {
		t.Errorf("expected mitigation required on empty human oversight")
	}
}

func TestQA_AdversarialExtremeInputSizes(t *testing.T) {
	evaluator := NewEvaluator()

	hugePurpose := strings.Repeat("detailed_intended_purpose_specification_", 2000)
	report := evaluator.ConductFRIA("system", "org", hugePurpose, []string{"1", "2"}, "human")

	if len(report.IntendedPurpose) < 50000 {
		t.Errorf("expected purpose stored completely")
	}
}
