package cemark

import (
	"testing"
)

func TestCEMark_GenerateDeclaration(t *testing.T) {
	generator := NewGenerator()

	doc := generator.GenerateDeclaration(
		"Enterprise Loan Decision Engine",
		"EuroBank AI SAS",
		"10 Boulevard Haussmann, 75009 Paris, France",
		"Jean Dupont",
		"Chief Compliance Officer",
		"Paris, France",
	)

	if !doc.CEMarkAffixed {
		t.Errorf("expected CE mark affixed")
	}

	if len(doc.StatutoryDirectives) < 2 {
		t.Errorf("expected at least 2 EU statutory directives cited")
	}
}

func TestCEMark_GenerateEUDatabaseEntry(t *testing.T) {
	generator := NewGenerator()

	entry := generator.GenerateEUDatabaseEntry(
		"TalentAI Screener",
		"HR Solutions GmbH",
		"Annex III.4 (Employment & Worker Management)",
		"Candidate evaluation for recruitment",
		"annex4-ref-12345",
		"eu-doc-ref-67890",
	)

	if entry.Status != "PLACED_ON_MARKET" {
		t.Errorf("unexpected status: %s", entry.Status)
	}

	if entry.TechnicalDocRef != "annex4-ref-12345" {
		t.Errorf("mismatched tech doc ref: %s", entry.TechnicalDocRef)
	}
}
