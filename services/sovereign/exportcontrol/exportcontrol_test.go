package exportcontrol

import (
	"testing"
)

func TestExport_FrontierComputeThreshold(t *testing.T) {
	engine := NewEngine()

	spec := ModelExportSpec{
		ModelName:          "Frontier-LLM-4",
		TotalTrainingFLOPs: 2.5e26, // Exceeds 10^26 threshold
		RecipientEntity:    "Allied-University-Lab",
		DestinationCountry: "Germany",
	}

	res := engine.ScreenModel(spec)
	if res.Requirement != LicenseRequired {
		t.Errorf("expected mandatory export license for frontier compute, got %s", res.Requirement)
	}
}

func TestExport_SanctionedEntityMatch(t *testing.T) {
	engine := NewEngine()

	spec := ModelExportSpec{
		ModelName:          "Standard-Vision-Model",
		RecipientEntity:    "sanctioned_entity_corp",
		DestinationCountry: "ThirdCountry",
	}

	res := engine.ScreenModel(spec)
	if res.Requirement != ProhibitedDenied {
		t.Errorf("expected prohibited denial for sanctioned entity, got %s", res.Requirement)
	}
}

func TestExport_EmbargoedCountry(t *testing.T) {
	engine := NewEngine()

	spec := ModelExportSpec{
		ModelName:          "Open-Source-Model",
		DestinationCountry: "North_Korea",
	}

	res := engine.ScreenModel(spec)
	if res.Requirement != ProhibitedDenied {
		t.Errorf("expected prohibited denial for embargoed destination")
	}
}

func TestExport_CleanNLRModel(t *testing.T) {
	engine := NewEngine()

	spec := ModelExportSpec{
		ModelName:          "Small-7B-Model",
		TotalTrainingFLOPs: 1e23,
		RecipientEntity:    "Friendly-Partner-Inc",
		DestinationCountry: "United Kingdom",
	}

	res := engine.ScreenModel(spec)
	if res.Requirement != NoLicenseRequired_NLR {
		t.Errorf("expected NLR for clean standard model, got %s", res.Requirement)
	}
}
