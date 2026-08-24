// Package fairness implements continuous demographic parity and disparate impact telemetry
// pursuant to EEOC 29 CFR §1607 (Four-Fifths Rule) and NYC LL144 (ARCHITECTURE.md §16).
package fairness

import (
	"time"
)

// GroupStatistics contains selection rates for a demographic cohort.
type GroupStatistics struct {
	GroupLabel    string  `json:"groupLabel"` // e.g. "female", "male", "protected_minority"
	TotalApplied  int64   `json:"totalApplied"`
	TotalSelected int64   `json:"totalSelected"`
	SelectionRate float64 `json:"selectionRate"` // TotalSelected / TotalApplied
}

// DisparateImpactFinding details the Four-Fifths rule calculation.
type DisparateImpactFinding struct {
	ProtectedGroup   string  `json:"protectedGroup"`
	BenchmarkGroup   string  `json:"benchmarkGroup"`
	ImpactRatio      float64 `json:"impactRatio"`      // SelectionRate(Protected) / SelectionRate(Benchmark)
	PassesFourFifths bool    `json:"passesFourFifths"` // True if ImpactRatio >= 0.80
	StatutoryStatus  string  `json:"statutoryStatus"`  // COMPLIANT | ADVERSE_IMPACT_VIOLATION
}

// FairnessScorecard summarizes real-time fairness across all demographic cohorts.
type FairnessScorecard struct {
	SystemName      string                   `json:"systemName"`
	TotalDecisions  int64                    `json:"totalDecisions"`
	GroupsEvaluated []GroupStatistics        `json:"groupsEvaluated"`
	Findings        []DisparateImpactFinding `json:"findings"`
	OverallFairness string                   `json:"overallFairness"` // FAIR_COMPLIANT | ADVERSE_IMPACT_ALERT
	AuditedAt       time.Time                `json:"auditedAt"`
}
