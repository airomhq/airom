package matrix

import (
	"strings"
	"testing"
)

func TestQA_AdversarialEmptyDomainInputs(t *testing.T) {
	harmonizer := NewHarmonizer()

	res := harmonizer.Harmonize("", "", nil)
	if res.OverallVerdict != "GLOBAL_PASS" || res.TotalFrameworks != 6 {
		t.Errorf("expected 6 frameworks on empty domain")
	}
}

func TestQA_AdversarialExtremeDomainStrings(t *testing.T) {
	harmonizer := NewHarmonizer()

	hugeDomain := strings.Repeat("financial_credit_underwriting_hr_recruitment_", 1000)
	res := harmonizer.Harmonize("System", hugeDomain, nil)

	if res.OverallVerdict != "REGIONAL_RESTRICTIONS" {
		t.Errorf("expected regional restrictions on high risk domain keywords")
	}
}
