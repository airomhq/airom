// Package classify implements automated EU AI Act risk tier and Annex III classification
// pursuant to Articles 5, 6, 50, and Annex III (ARCHITECTURE.md §16).
package classify

import (
	"time"
)

// RiskTier categorizes the statutory tier under the EU AI Act.
type RiskTier string

const (
	TierUnacceptableRisk     RiskTier = "UNACCEPTABLE_RISK"     // Article 5 (Prohibited practices)
	TierHighRisk             RiskTier = "HIGH_RISK"             // Article 6 & Annex III (FRIA & Conformity mandatory)
	TierSpecificTransparency RiskTier = "SPECIFIC_TRANSPARENCY" // Article 50 (Watermarking & Disclosure mandatory)
	TierMinimalRisk          RiskTier = "MINIMAL_RISK"          // Article 69 (Voluntary codes of conduct)
)

// AnnexIIICategory identifies high-risk application domains under EU AI Act Annex III.
type AnnexIIICategory string

const (
	AnnexIII_1_Biometrics          AnnexIIICategory = "1_Biometrics_Remote_Identification"
	AnnexIII_2_CriticalInfra       AnnexIIICategory = "2_Critical_Infrastructure"
	AnnexIII_3_EducationVocational AnnexIIICategory = "3_Education_and_Vocational_Training"
	AnnexIII_4_EmploymentHR        AnnexIIICategory = "4_Employment_Worker_Management"
	AnnexIII_5_EssentialServices   AnnexIIICategory = "5_Essential_Public_and_Private_Services"
	AnnexIII_6_LawEnforcement      AnnexIIICategory = "6_Law_Enforcement"
	AnnexIII_7_MigrationAsylum     AnnexIIICategory = "7_Migration_Asylum_Border_Control"
	AnnexIII_8_DemocraticProcesses AnnexIIICategory = "8_Administration_of_Justice_Democracy"
)

// ClassificationResult details the EU AI Act risk determination for an AI system.
type ClassificationResult struct {
	SystemName       string            `json:"systemName"`
	Tier             RiskTier          `json:"tier"`
	AnnexIIICategory *AnnexIIICategory `json:"annexIiiCategory,omitempty"`
	StatutoryBasis   string            `json:"statutoryBasis"`
	MandatoryActions []string          `json:"mandatoryActions"`
	ProhibitedReason string            `json:"prohibitedReason,omitempty"`
	ClassifiedAt     time.Time         `json:"classifiedAt"`
}
