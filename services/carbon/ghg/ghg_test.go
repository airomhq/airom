package ghg

import (
	"testing"
)

func TestGHG_GenerateStatutoryReport_California(t *testing.T) {
	accountant := NewAccountant()

	// 1,000,000 kWh Scope 2 (training cluster) + 500,000 kWh Scope 3 (API tokens)
	report := accountant.GenerateStatutoryReport(
		"Enterprise-AI-Corp",
		2026,
		Grid_US_CAISO_California,
		1000000.0,
		500000.0,
	)

	if report.TotalEnergyKWh != 1500000.0 || report.TotalMWh != 1500.0 {
		t.Errorf("energy sum error: %+v", report)
	}

	// 1.5M kWh * 210 g/kWh = 315,000,000 g = 315.0 tons CO2e
	expectedTons := 315.0
	if report.TotalEmissionsTonsCO2 != expectedTons {
		t.Errorf("expected %f tons CO2e, got %f", expectedTons, report.TotalEmissionsTonsCO2)
	}

	if len(report.StatutoryMandates) != 3 {
		t.Errorf("expected 3 statutory mandates cited, got %d", len(report.StatutoryMandates))
	}
}

func TestGHG_LowCarbonGrid_Sweden(t *testing.T) {
	accountant := NewAccountant()

	// 1,000,000 kWh in Sweden (20 g/kWh) -> 20.0 tons CO2e
	report := accountant.GenerateStatutoryReport(
		"Nordic-AI-AB",
		2026,
		Grid_EU_Sweden_Hydro,
		1000000.0,
		0,
	)

	if report.TotalEmissionsTonsCO2 != 20.0 {
		t.Errorf("expected 20.0 tons CO2e in Sweden hydro grid, got %f", report.TotalEmissionsTonsCO2)
	}
}
