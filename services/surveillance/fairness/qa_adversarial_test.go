package fairness

import (
	"testing"
)

func TestQA_AdversarialEmptyAndZeroApplications(t *testing.T) {
	engine := NewTelemetryEngine()

	// Zero applicants across all cohorts
	groups := []GroupStatistics{
		{GroupLabel: "Cohort_Zero", TotalApplied: 0, TotalSelected: 0},
	}

	sc := engine.EvaluateFairness("Empty-App", groups)
	if sc.OverallFairness != "FAIR_COMPLIANT" || sc.TotalDecisions != 0 {
		t.Errorf("expected clean handle of 0 applicants: %+v", sc)
	}
}

func TestQA_AdversarialSingleGroup(t *testing.T) {
	engine := NewTelemetryEngine()

	groups := []GroupStatistics{
		{GroupLabel: "Solo_Cohort", TotalApplied: 100, TotalSelected: 50},
	}

	sc := engine.EvaluateFairness("Solo-App", groups)
	if len(sc.Findings) != 0 {
		t.Errorf("expected 0 disparate impact findings when only 1 group exists")
	}
}
