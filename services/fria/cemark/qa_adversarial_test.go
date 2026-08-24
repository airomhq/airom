package cemark

import (
	"strings"
	"testing"
)

func TestQA_AdversarialEmptyStrings(t *testing.T) {
	generator := NewGenerator()

	doc := generator.GenerateDeclaration("", "", "", "", "", "")
	if !doc.CEMarkAffixed {
		t.Errorf("expected CE mark affixed even on empty string fields")
	}

	entry := generator.GenerateEUDatabaseEntry("", "", "", "", "", "")
	if entry.Status != "PLACED_ON_MARKET" {
		t.Errorf("expected valid status")
	}
}

func TestQA_AdversarialExtremeProviderStrings(t *testing.T) {
	generator := NewGenerator()

	hugeAddress := strings.Repeat("corporate_headquarters_eu_member_state_address_line_", 1000)
	doc := generator.GenerateDeclaration("system", "provider", hugeAddress, "signer", "role", "place")

	if len(doc.ProviderAddress) < 20000 {
		t.Errorf("expected huge address preserved")
	}
}
