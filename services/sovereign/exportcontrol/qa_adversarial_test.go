package exportcontrol

import (
	"testing"
)

func TestQA_AdversarialCaseAndWhitespaceEvasions(t *testing.T) {
	engine := NewEngine()

	// Mixed casing with surrounding whitespace
	spec := ModelExportSpec{
		ModelName:          "Model",
		RecipientEntity:    "  SANCTIONED_ENTITY_CORP  ",
		DestinationCountry: "  iRaN  ",
	}

	res := engine.ScreenModel(spec)
	if res.Requirement != ProhibitedDenied {
		t.Errorf("evasion successful: entity/country normalization failed")
	}
}

func TestQA_AdversarialExtremeComputeFloats(t *testing.T) {
	engine := NewEngine()

	spec := ModelExportSpec{
		ModelName:          "Super-AGI",
		TotalTrainingFLOPs: 1e30, // 10^30 FLOPs
		DestinationCountry: "Switzerland",
	}

	res := engine.ScreenModel(spec)
	if res.Requirement != LicenseRequired {
		t.Errorf("expected mandatory export license for super-frontier compute")
	}
}
