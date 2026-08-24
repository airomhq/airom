// Package exportcontrol implements AI export controls, compute threshold enforcement,
// and entity list sanctions screening pursuant to US BIS EAR and EU Dual-Use Regulations (ARCHITECTURE.md §16).
package exportcontrol

import (
	"time"
)

// LicenseRequirement classifies the regulatory export authorization requirement.
type LicenseRequirement string

const (
	LicenseRequired       LicenseRequirement = "EXPORT_LICENSE_MANDATORY"
	NoLicenseRequired_NLR LicenseRequirement = "NO_LICENSE_REQUIRED_NLR"
	ProhibitedDenied      LicenseRequirement = "EXPORT_PROHIBITED_DENIED"
)

// ModelExportSpec defines the technical and recipient characteristics of a model export.
type ModelExportSpec struct {
	ModelName          string  `json:"modelName"`
	TotalTrainingFLOPs float64 `json:"totalTrainingFlops"` // e.g. 1e26
	TotalParametersB   float64 `json:"totalParametersB"`   // Parameter count in billions
	RecipientEntity    string  `json:"recipientEntity"`
	DestinationCountry string  `json:"destinationCountry"`
	RestrictedDualUse  bool    `json:"restrictedDualUse"`
}

// ExportScreeningResult details the statutory export control determination.
type ExportScreeningResult struct {
	ModelName         string             `json:"modelName"`
	Requirement       LicenseRequirement `json:"requirement"`
	TriggeredControls []string           `json:"triggeredControls"`
	StatutoryBasis    string             `json:"statutoryBasis"`
	ScreenedAt        time.Time          `json:"screenedAt"`
}
