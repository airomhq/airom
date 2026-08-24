// Package assessment implements the statutory Fundamental Rights Impact Assessment (FRIA)
// workflow pursuant to EU AI Act Article 27 (ARCHITECTURE.md §16).
package assessment

import (
	"time"
)

// FundamentalRight categorizes human rights protected under the EU Charter of Fundamental Rights.
type FundamentalRight string

const (
	RightHumanDignity       FundamentalRight = "human_dignity"        // Charter Art 1
	RightNonDiscrimination  FundamentalRight = "non_discrimination"   // Charter Art 21
	RightPrivacyDataProtect FundamentalRight = "privacy_data_protect" // Charter Art 7 & 8
	RightFreedomExpression  FundamentalRight = "freedom_expression"   // Charter Art 11
	RightFairTrialEffective FundamentalRight = "fair_trial"           // Charter Art 47
	RightEnvironmental      FundamentalRight = "environmental_impact" // Charter Art 37
)

// RightsRiskExposure details the assessed impact on a specific fundamental right.
type RightsRiskExposure struct {
	Right           FundamentalRight `json:"right"`
	RiskLevel       string           `json:"riskLevel"` // HIGH | MEDIUM | LOW
	IdentifiedHarms []string         `json:"identifiedHarms"`
	Mitigations     []string         `json:"mitigations"`
	ResidualRisk    string           `json:"residualRisk"` // ACCEPTABLE | REQUIRES_ADDITIONAL_CONTROLS
}

// FRIAReport contains the complete statutory assessment under EU AI Act Article 27.
type FRIAReport struct {
	AssessmentID         string               `json:"assessmentId"`
	SystemName           string               `json:"systemName"`
	DeployerOrganization string               `json:"deployerOrganization"`
	IntendedPurpose      string               `json:"intendedPurpose"`
	AffectedPersons      []string             `json:"affectedPersons"`
	RightsAssessed       []RightsRiskExposure `json:"rightsAssessed"`
	HumanOversightModel  string               `json:"humanOversightModel"`
	StatutoryVerdict     string               `json:"statutoryVerdict"` // APPROVED_FOR_DEPLOYMENT | MITIGATION_REQUIRED
	AssessedAt           time.Time            `json:"assessedAt"`
}
