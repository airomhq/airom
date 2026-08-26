// Package treaty evaluates frontier AI models against international safety treaties
// including the Bletchley Park Declaration, Seoul AI Safety Commitments, and G7 Hiroshima Process.
package treaty

import (
	"time"
)

// TreatyFramework enumerates international AI safety treaty accords.
type TreatyFramework string

const (
	TreatyBletchleyPark TreatyFramework = "BLETCHLEY_PARK_DECLARATION"
	TreatySeoulSummit   TreatyFramework = "SEOUL_AI_SAFETY_COMMITMENTS"
	TreatyG7Hiroshima   TreatyFramework = "G7_HIROSHIMA_AI_PROCESS"
)

// FrontierSafetyCommitments defines mandatory safety controls for frontier AI models (>10^26 FLOPs).
type FrontierSafetyCommitments struct {
	ModelName                string  `json:"modelName"`
	EstimatedFLOPs           float64 `json:"estimatedFLOPs"` // e.g. 1e26
	HasIndependentRedTeam    bool    `json:"hasIndependentRedTeam"`
	HasCBRNEvaluation        bool    `json:"hasCBRNEvaluation"` // Chemical, Biological, Radiological, Nuclear risks
	HasCyberOffenseLimits    bool    `json:"hasCyberOffenseLimits"`
	HasEmergencyKillSwitch   bool    `json:"hasEmergencyKillSwitch"`
	ResponsibleScalingPolicy bool    `json:"responsibleScalingPolicy"`
}

// TreatyEvaluationResult models the international treaty compliance verdict.
type TreatyEvaluationResult struct {
	ModelName    string          `json:"modelName"`
	Framework    TreatyFramework `json:"framework"`
	IsConformant bool            `json:"isConformant"`
	Violations   []string        `json:"violations"`
	EvaluatedAt  time.Time       `json:"evaluatedAt"`
}
