// Package impact evaluates the blast radius of new legislative bills against enterprise AI inventories.
package impact

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// RiskLevel defines the regulatory urgency of an impact finding.
type RiskLevel string

const (
	RiskCritical      RiskLevel = "CRITICAL_NON_COMPLIANCE"
	RiskHigh          RiskLevel = "HIGH_COMPLIANCE_BURDEN"
	RiskMedium        RiskLevel = "MODERATE_DISCLOSURE"
	RiskInformational RiskLevel = "INFORMATIONAL_MONITOR"
)

// MandateCondition defines matching criteria for a statutory rule.
type MandateCondition struct {
	MandateID          string              `json:"mandateId"`   // e.g. "CA-SB1047-FLOP-GATE", "MA-AEDT-AUDIT"
	StatuteCite        string              `json:"statuteCite"` // e.g. "Cal. SB 1047 § 22602"
	TargetKind         airom.ComponentKind `json:"targetKind"`
	MinParamCount      int64               `json:"minParamCount,omitempty"` // e.g. >10B parameters
	RequiresKillSwitch bool                `json:"requiresKillSwitch,omitempty"`
	RiskLevel          RiskLevel           `json:"riskLevel"`
	Description        string              `json:"description"`
}

// AffectedComponent maps a discovered component to a triggered statutory mandate.
type AffectedComponent struct {
	ComponentID    airom.ID  `json:"componentId"`
	ComponentName  string    `json:"componentName"`
	Kind           string    `json:"kind"`
	MandateID      string    `json:"mandateId"`
	StatuteCite    string    `json:"statuteCite"`
	RiskLevel      RiskLevel `json:"riskLevel"`
	RequiredAction string    `json:"requiredAction"`
}

// ImpactAssessment aggregates all triggered mandates for an inventory.
type ImpactAssessment struct {
	AssessmentID       string              `json:"assessmentId"`
	BillID             string              `json:"billId"`
	TotalComponents    int                 `json:"totalComponents"`
	AffectedCount      int                 `json:"affectedCount"`
	HighestRisk        RiskLevel           `json:"highestRisk"`
	AffectedComponents []AffectedComponent `json:"affectedComponents"`
	EvaluatedAt        time.Time           `json:"evaluatedAt"`
}
