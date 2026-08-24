// Package annex4 implements automated EU AI Act Annex IV Technical Documentation generation
// pursuant to Article 11 and Annex IV (ARCHITECTURE.md §16).
package annex4

import (
	"time"
)

// TechnicalDocSection identifies the 6 mandatory statutory sections under Annex IV.
type TechnicalDocSection string

const (
	Section1_GeneralDescription      TechnicalDocSection = "1_General_Description_and_Intended_Purpose"
	Section2_ComponentSpecifications TechnicalDocSection = "2_Detailed_Component_and_Hardware_Specs"
	Section3_DevelopmentAndTraining  TechnicalDocSection = "3_Development_Training_Validation_Testing"
	Section4_MonitoringAndControl    TechnicalDocSection = "4_Monitoring_Functioning_and_Oversight"
	Section5_RiskManagementSystem    TechnicalDocSection = "5_Risk_Management_System_Summary"
	Section6_LifecycleModifications  TechnicalDocSection = "6_Lifecycle_Modifications_and_Traceability"
)

// AnnexIVDocument represents the complete technical documentation bundle.
type AnnexIVDocument struct {
	DocumentID        string                         `json:"documentId"`
	SystemName        string                         `json:"systemName"`
	Provider          string                         `json:"provider"`
	Version           string                         `json:"version"`
	Sections          map[TechnicalDocSection]string `json:"sections"`
	AIBOMFingerprint  string                         `json:"aibomFingerprint"`
	StatutoryCitation string                         `json:"statutoryCitation"`
	GeneratedAt       time.Time                      `json:"generatedAt"`
}
