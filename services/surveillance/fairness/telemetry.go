package fairness

import (
	"time"
)

// TelemetryEngine computes continuous demographic parity and disparate impact ratios.
type TelemetryEngine struct{}

// NewTelemetryEngine constructs a fairness telemetry engine.
func NewTelemetryEngine() *TelemetryEngine {
	return &TelemetryEngine{}
}

// EvaluateFairness audits group selection rates against the EEOC Four-Fifths (80%) Rule.
func (te *TelemetryEngine) EvaluateFairness(systemName string, groups []GroupStatistics) FairnessScorecard {
	scorecard := FairnessScorecard{
		SystemName:      systemName,
		GroupsEvaluated: make([]GroupStatistics, len(groups)),
		OverallFairness: "FAIR_COMPLIANT",
		AuditedAt:       time.Now().UTC(),
	}

	var maxSelectionRate float64
	var benchmarkGroup string

	// 1. Calculate selection rates and find benchmark
	for i, g := range groups {
		if g.TotalApplied > 0 {
			g.SelectionRate = float64(g.TotalSelected) / float64(g.TotalApplied)
		}
		scorecard.GroupsEvaluated[i] = g
		scorecard.TotalDecisions += g.TotalApplied

		if g.SelectionRate > maxSelectionRate {
			maxSelectionRate = g.SelectionRate
			benchmarkGroup = g.GroupLabel
		}
	}

	if maxSelectionRate == 0 {
		return scorecard
	}

	// 2. Compute Disparate Impact Ratios against benchmark
	for _, g := range scorecard.GroupsEvaluated {
		if g.GroupLabel == benchmarkGroup {
			continue
		}

		ratio := g.SelectionRate / maxSelectionRate
		passes := ratio >= 0.80

		status := "COMPLIANT"
		if !passes {
			status = "ADVERSE_IMPACT_VIOLATION (EEOC 29 CFR § 1607 / NYC LL144)"
			scorecard.OverallFairness = "ADVERSE_IMPACT_ALERT"
		}

		scorecard.Findings = append(scorecard.Findings, DisparateImpactFinding{
			ProtectedGroup:   g.GroupLabel,
			BenchmarkGroup:   benchmarkGroup,
			ImpactRatio:      ratio,
			PassesFourFifths: passes,
			StatutoryStatus:  status,
		})
	}

	return scorecard
}
