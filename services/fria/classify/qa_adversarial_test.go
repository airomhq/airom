package classify

import (
	"testing"
)

func TestQA_AdversarialEmptyDomainInputs(t *testing.T) {
	engine := NewEngine()

	res := engine.ClassifySystem("", "", nil)
	if res.Tier != TierMinimalRisk {
		t.Errorf("expected minimal risk for empty input, got %s", res.Tier)
	}
}

func TestQA_AdversarialCaseAndWhitespaceEvasion(t *testing.T) {
	engine := NewEngine()

	evasionDomains := []string{
		"  BIOMETRIC_IDENTIFICATION  ",
		"rEcRuItMeNt_Hr",
		"SoCiAl_ScOrInG",
	}

	for _, d := range evasionDomains {
		res := engine.ClassifySystem("system", d, nil)
		if res.Tier == TierMinimalRisk {
			t.Errorf("failed to classify obfuscated domain %s", d)
		}
	}
}
