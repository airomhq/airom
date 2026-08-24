// Package ghg implements statutory AI greenhouse gas (GHG) Scope 2 & 3 carbon disclosures
// pursuant to California SB 219, California SB 253, and EU CSDDD (ARCHITECTURE.md §16).
package ghg

import (
	"time"
)

// GridRegion identifies the regional electricity grid with distinct carbon intensity.
type GridRegion string

const (
	Grid_US_CAISO_California GridRegion = "us_caiso_california" // ~210 gCO2/kWh
	Grid_US_ERCOT_Texas      GridRegion = "us_ercot_texas"      // ~380 gCO2/kWh
	Grid_US_PJM_East         GridRegion = "us_pjm_east"         // ~340 gCO2/kWh
	Grid_EU_France_Nuclear   GridRegion = "eu_france"           // ~55 gCO2/kWh
	Grid_EU_Germany_Mixed    GridRegion = "eu_germany"          // ~320 gCO2/kWh
	Grid_EU_Sweden_Hydro     GridRegion = "eu_sweden_nordic"    // ~20 gCO2/kWh
)

// CarbonScope categorizes emissions under the GHG Protocol Corporate Standard.
type CarbonScope string

const (
	Scope2_IndirectElectricity CarbonScope = "Scope_2_Indirect_Electricity"
	Scope3_UpstreamCloudAI     CarbonScope = "Scope_3_Upstream_Cloud_AI_API"
)

// StatutoryGHGReport contains legally conforming carbon accounting metrics.
type StatutoryGHGReport struct {
	ReportID                string     `json:"reportId"`
	Organization            string     `json:"organization"`
	ReportingYear           int        `json:"reportingYear"`
	TotalEnergyKWh          float64    `json:"totalEnergyKwh"`
	TotalMWh                float64    `json:"totalMwh"`
	TotalEmissionsTonsCO2   float64    `json:"totalEmissionsTonsCo2e"` // Metric tons CO2e
	Scope2EmissionsTons     float64    `json:"scope2EmissionsTons"`
	Scope3EmissionsTons     float64    `json:"scope3EmissionsTons"`
	GridRegion              GridRegion `json:"gridRegion"`
	GridIntensityGCO2perKWh float64    `json:"gridIntensityGco2PerKwh"`
	StatutoryMandates       []string   `json:"statutoryMandates"`
	GeneratedAt             time.Time  `json:"generatedAt"`
}
