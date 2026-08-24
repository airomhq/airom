package ghg

import (
	"testing"
)

func TestQA_AdversarialZeroEnergyAccounting(t *testing.T) {
	accountant := NewAccountant()

	report := accountant.GenerateStatutoryReport("Zero-Corp", 2026, Grid_US_CAISO_California, 0, 0)
	if report.TotalEnergyKWh != 0 || report.TotalEmissionsTonsCO2 != 0 {
		t.Errorf("expected 0 emissions for zero energy: %+v", report)
	}
}

func TestQA_AdversarialUnknownGridRegion(t *testing.T) {
	accountant := NewAccountant()

	report := accountant.GenerateStatutoryReport("Global-Corp", 2026, "unknown_region", 1000000.0, 0)
	if report.GridIntensityGCO2perKWh != 250.0 {
		t.Errorf("expected global default 250 g/kWh for unknown region, got %f", report.GridIntensityGCO2perKWh)
	}
	if report.TotalEmissionsTonsCO2 <= 0 {
		t.Errorf("expected positive emissions using fallback")
	}
}
