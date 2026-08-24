// Package matrix implements the unified global cross-jurisdiction AI regulatory harmonizer
// (ARCHITECTURE.md §16).
package matrix

import (
	"time"
)

// GlobalFramework identifies sovereign legal frameworks.
type GlobalFramework string

const (
	FrameworkEU_AI_Act          GlobalFramework = "EU_AI_Act_2024_1689"
	FrameworkUS_EO_NIST         GlobalFramework = "US_EO_14110_NIST_AI_100_1"
	FrameworkUK_ProInnovation   GlobalFramework = "UK_AI_Pro_Innovation_Framework"
	FrameworkJapan_Guidelines   GlobalFramework = "Japan_METI_MIC_AI_Guidelines"
	FrameworkSingapore_ModelGov GlobalFramework = "Singapore_IMDA_Model_AI_Gov"
	FrameworkChina_Generative   GlobalFramework = "China_CAC_Generative_AI_Measures"
)

// FrameworkVerdict details compliance status under a specific sovereign framework.
type FrameworkVerdict struct {
	Framework       GlobalFramework `json:"framework"`
	Jurisdiction    string          `json:"jurisdiction"`
	Status          string          `json:"status"` // COMPLIANT | GAP_IDENTIFIED | PROHIBITED
	StatutoryBasis  string          `json:"statutoryBasis"`
	RequiredFilings []string        `json:"requiredFilings"`
}

// GlobalComplianceMatrix captures unified compliance across all sovereign frameworks.
type GlobalComplianceMatrix struct {
	SystemName      string                               `json:"systemName"`
	OverallVerdict  string                               `json:"overallVerdict"` // GLOBAL_PASS | REGIONAL_RESTRICTIONS | PROHIBITED
	Verdicts        map[GlobalFramework]FrameworkVerdict `json:"verdicts"`
	TotalFrameworks int                                  `json:"totalFrameworks"`
	CompliantCount  int                                  `json:"compliantCount"`
	HarmonizedAt    time.Time                            `json:"harmonizedAt"`
}
