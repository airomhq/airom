package exportcontrol

import (
	"strings"
	"time"
)

// Engine screens AI models and compute against export control and sanctions regimes.
type Engine struct {
	restrictedEntities map[string]bool
	embargoedCountries map[string]bool
}

// NewEngine constructs an export control screening engine.
func NewEngine() *Engine {
	return &Engine{
		restrictedEntities: map[string]bool{
			"sanctioned_entity_corp":  true,
			"prohibited_defense_lab":  true,
			"unverified_end_user_ltd": true,
		},
		embargoedCountries: map[string]bool{
			"cuba":        true,
			"iran":        true,
			"north_korea": true,
			"syria":       true,
			"crimea":      true,
		},
	}
}

// ScreenModel evaluates a model export request against BIS EAR and EU dual-use regulations.
func (e *Engine) ScreenModel(spec ModelExportSpec) ExportScreeningResult {
	res := ExportScreeningResult{
		ModelName:   spec.ModelName,
		Requirement: NoLicenseRequired_NLR,
		ScreenedAt:  time.Now().UTC(),
	}

	normEntity := strings.ToLower(strings.TrimSpace(spec.RecipientEntity))
	normCountry := strings.ToLower(strings.TrimSpace(spec.DestinationCountry))

	// 1. Embargoed Country Check
	if e.embargoedCountries[normCountry] {
		res.Requirement = ProhibitedDenied
		res.TriggeredControls = append(res.TriggeredControls, "Comprehensive Country-Level Embargo (15 CFR §746)")
		res.StatutoryBasis = "US Export Administration Regulations (EAR) Comprehensive Sanctions"
		return res
	}

	// 2. Restricted Entity List Check
	if e.restrictedEntities[normEntity] {
		res.Requirement = ProhibitedDenied
		res.TriggeredControls = append(res.TriggeredControls, "BIS Entity List Match (15 CFR §744)")
		res.StatutoryBasis = "US Department of Commerce Bureau of Industry and Security (BIS) Entity List"
		return res
	}

	// 3. Frontier Dual-Use Compute Threshold Check (FLOPs >= 1e26)
	const frontierFLOPsThreshold = 1e26
	if spec.TotalTrainingFLOPs >= frontierFLOPsThreshold {
		res.Requirement = LicenseRequired
		res.TriggeredControls = append(res.TriggeredControls, "Frontier Dual-Use AI Model Compute Threshold Exceeded (>= 10^26 FLOPs)")
		res.StatutoryBasis = "White House Executive Order on Safe, Secure, and Trustworthy AI & BIS Interim Final Rule"
	}

	// 4. Specific Dual-Use / Defense Model Flags
	if spec.RestrictedDualUse {
		res.Requirement = LicenseRequired
		res.TriggeredControls = append(res.TriggeredControls, "CBRN / Cyber Offensive Dual-Use Capability Classification")
		res.StatutoryBasis = "EU Dual-Use Regulation (EU) 2021/821 & US Commerce Control List Category 4/5"
	}

	if len(res.TriggeredControls) == 0 {
		res.StatutoryBasis = "EAR99 / Dual-Use General Authorization (NLR)"
	}

	return res
}
