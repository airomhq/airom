// Package scorecard computes OpenSSF AI Model Security Scorecards for AI supply chain trust.
package scorecard

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// CheckID identifies an OpenSSF AI security criteria.
type CheckID string

const (
	CheckSignedCheckpoints       CheckID = "SIGNED_MODEL_CHECKPOINTS"
	CheckDatasetProvenance       CheckID = "DATASET_LINEAGE_PROVENANCE"
	CheckModelCardTransparency   CheckID = "MODEL_CARD_TRANSPARENCY"
	CheckVulnerabilityDisclosure CheckID = "VULNERABILITY_DISCLOSURE"
	CheckLicensingClarity        CheckID = "LICENSING_CLARITY"
	CheckTrojanScanning          CheckID = "TROJAN_WEIGHT_FORENSICS"
)

// CheckResult represents the outcome of an individual OpenSSF check.
type CheckResult struct {
	CheckID     CheckID `json:"checkId"`
	Name        string  `json:"name"`
	Score       float64 `json:"score"` // 0.0 to 10.0
	Passed      bool    `json:"passed"`
	Reason      string  `json:"reason"`
	EvidenceRef string  `json:"evidenceRef,omitempty"`
}

// ModelScorecard aggregates all OpenSSF security checks for an AI component.
type ModelScorecard struct {
	ComponentID   airom.ID      `json:"componentId"`
	ComponentName string        `json:"componentName"`
	OverallScore  float64       `json:"overallScore"` // 0.0 to 10.0 (weighted average)
	PassingGrade  bool          `json:"passingGrade"` // true if >= 7.0
	Checks        []CheckResult `json:"checks"`
	EvaluatedAt   time.Time     `json:"evaluatedAt"`
}

// InventoryScorecard summarizes OpenSSF health across an entire AIBOM.
type InventoryScorecard struct {
	TotalModels     int              `json:"totalModels"`
	PassingModels   int              `json:"passingModels"`
	AverageScore    float64          `json:"averageScore"`
	ModelScorecards []ModelScorecard `json:"modelScorecards"`
	EvaluatedAt     time.Time        `json:"evaluatedAt"`
}
