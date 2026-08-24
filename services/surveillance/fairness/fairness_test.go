package fairness

import (
	"testing"
)

func TestFairness_PassesFourFifthsRule(t *testing.T) {
	engine := NewTelemetryEngine()

	groups := []GroupStatistics{
		{GroupLabel: "Cohort_A", TotalApplied: 1000, TotalSelected: 500}, // 50%
		{GroupLabel: "Cohort_B", TotalApplied: 1000, TotalSelected: 450}, // 45% (ratio = 0.90 >= 0.80)
	}

	sc := engine.EvaluateFairness("Talent-Ranker", groups)
	if sc.OverallFairness != "FAIR_COMPLIANT" {
		t.Errorf("expected FAIR_COMPLIANT, got %s", sc.OverallFairness)
	}

	if len(sc.Findings) != 1 || !sc.Findings[0].PassesFourFifths {
		t.Errorf("expected passing Four-Fifths finding: %+v", sc.Findings)
	}
}

func TestFairness_AdverseImpactViolation(t *testing.T) {
	engine := NewTelemetryEngine()

	groups := []GroupStatistics{
		{GroupLabel: "Male", TotalApplied: 1000, TotalSelected: 600},   // 60% (Benchmark)
		{GroupLabel: "Female", TotalApplied: 1000, TotalSelected: 300}, // 30% (ratio = 0.50 < 0.80)
	}

	sc := engine.EvaluateFairness("Autonomous-Promotion-Bot", groups)
	if sc.OverallFairness != "ADVERSE_IMPACT_ALERT" {
		t.Errorf("expected ADVERSE_IMPACT_ALERT, got %s", sc.OverallFairness)
	}

	if len(sc.Findings) != 1 || sc.Findings[0].PassesFourFifths {
		t.Errorf("expected failing Four-Fifths finding: %+v", sc.Findings)
	}

	if sc.Findings[0].ImpactRatio != 0.50 {
		t.Errorf("expected impact ratio 0.50, got %f", sc.Findings[0].ImpactRatio)
	}
}
