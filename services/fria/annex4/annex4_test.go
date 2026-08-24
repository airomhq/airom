package annex4

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestAnnex4_GenerateTechnicalDoc(t *testing.T) {
	generator := NewGenerator()

	inv := &airom.Inventory{
		Components: []airom.Component{
			{ID: "c1", Kind: airom.KindHostedLLM, Name: "gpt-4o"},
			{ID: "c2", Kind: airom.KindVectorDB, Name: "qdrant"},
		},
	}

	doc := generator.GenerateTechnicalDoc(
		"High-Risk Diagnostic AI",
		"MedTech Europe Ltd",
		"v2.1.0",
		"Clinical decision assistance in radiological workflows",
		inv,
	)

	if len(doc.Sections) != 6 {
		t.Errorf("expected 6 statutory sections under Annex IV, got %d", len(doc.Sections))
	}

	for _, sec := range []TechnicalDocSection{
		Section1_GeneralDescription, Section2_ComponentSpecifications,
		Section3_DevelopmentAndTraining, Section4_MonitoringAndControl,
		Section5_RiskManagementSystem, Section6_LifecycleModifications,
	} {
		if content, ok := doc.Sections[sec]; !ok || len(content) == 0 {
			t.Errorf("missing or empty statutory section: %s", sec)
		}
	}
}

func TestAnnex4_NilInventory(t *testing.T) {
	generator := NewGenerator()

	doc := generator.GenerateTechnicalDoc("System", "Provider", "1.0", "Purpose", nil)
	if len(doc.Sections) != 6 {
		t.Errorf("expected 6 sections on nil inventory")
	}
}
