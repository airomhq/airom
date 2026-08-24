package ghg

import (
	"fmt"
	"time"
)

// Accountant translates AI energy consumption into statutory GHG disclosures.
type Accountant struct {
	gridIntensityCatalog map[GridRegion]float64
}

// NewAccountant constructs a GHG accountant.
func NewAccountant() *Accountant {
	catalog := map[GridRegion]float64{
		Grid_US_CAISO_California: 210.0, // gCO2 / kWh
		Grid_US_ERCOT_Texas:      380.0,
		Grid_US_PJM_East:         340.0,
		Grid_EU_France_Nuclear:   55.0,
		Grid_EU_Germany_Mixed:    320.0,
		Grid_EU_Sweden_Hydro:     20.0,
	}
	return &Accountant{gridIntensityCatalog: catalog}
}

// GenerateStatutoryReport computes emissions and formats compliance disclosures.
func (a *Accountant) GenerateStatutoryReport(org string, year int, region GridRegion, scope2KWh, scope3KWh float64) StatutoryGHGReport {
	intensity, ok := a.gridIntensityCatalog[region]
	if !ok {
		intensity = 250.0 // Global average baseline
	}

	totalKWh := scope2KWh + scope3KWh
	totalMWh := totalKWh / 1000.0

	// Emissions (tons CO2e) = (kWh * (gCO2/kWh)) / 1,000,000 g/ton
	scope2Tons := (scope2KWh * intensity) / 1e6
	scope3Tons := (scope3KWh * intensity) / 1e6
	totalTons := (totalKWh * intensity) / 1e6

	return StatutoryGHGReport{
		ReportID:                fmt.Sprintf("ghg-%s-%d-%d", org, year, time.Now().UnixNano()),
		Organization:            org,
		ReportingYear:           year,
		TotalEnergyKWh:          totalKWh,
		TotalMWh:                totalMWh,
		TotalEmissionsTonsCO2:   totalTons,
		Scope2EmissionsTons:     scope2Tons,
		Scope3EmissionsTons:     scope3Tons,
		GridRegion:              region,
		GridIntensityGCO2perKWh: intensity,
		StatutoryMandates: []string{
			"California Climate Corporate Data Accountability Act (SB 253 / SB 219)",
			"EU Corporate Sustainability Due Diligence Directive (CSDDD)",
			"EU Artificial Intelligence Act Article 53(1)(a) Energy Disclosures",
		},
		GeneratedAt: time.Now().UTC(),
	}
}
