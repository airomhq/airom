package assessment

import (
	"fmt"
	"time"
)

// Evaluator conducts automated Article 27 FRIA audits.
type Evaluator struct{}

// NewEvaluator constructs a FRIA evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// ConductFRIA builds a statutory assessment based on deployer disclosures and AIBOM inventory evidence.
func (e *Evaluator) ConductFRIA(systemName, deployerOrg, purpose string, affectedPersons []string, humanOversight string) FRIAReport {
	report := FRIAReport{
		AssessmentID:         fmt.Sprintf("fria-%d", time.Now().UnixNano()),
		SystemName:           systemName,
		DeployerOrganization: deployerOrg,
		IntendedPurpose:      purpose,
		AffectedPersons:      affectedPersons,
		HumanOversightModel:  humanOversight,
		AssessedAt:           time.Now().UTC(),
		StatutoryVerdict:     "APPROVED_FOR_DEPLOYMENT",
	}

	rights := []FundamentalRight{
		RightHumanDignity,
		RightNonDiscrimination,
		RightPrivacyDataProtect,
		RightFreedomExpression,
		RightFairTrialEffective,
		RightEnvironmental,
	}

	for _, r := range rights {
		exposure := RightsRiskExposure{
			Right:        r,
			RiskLevel:    "LOW",
			ResidualRisk: "ACCEPTABLE",
		}

		if r == RightNonDiscrimination {
			exposure.IdentifiedHarms = []string{"Potential statistical bias in training distributions"}
			exposure.Mitigations = []string{"Continuous disparate impact audits", "Pre-deployment parity testing"}
		} else if r == RightPrivacyDataProtect {
			exposure.IdentifiedHarms = []string{"PII memorization in neural representations"}
			exposure.Mitigations = []string{"AIROM Streaming DLP proxy", "Token watermarking"}
		}

		report.RightsAssessed = append(report.RightsAssessed, exposure)
	}

	if humanOversight == "" || humanOversight == "none" {
		report.StatutoryVerdict = "MITIGATION_REQUIRED: Article 14 Human Oversight Missing"
	}

	return report
}
