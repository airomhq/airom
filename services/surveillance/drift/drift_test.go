package drift

import (
	"testing"
)

func TestDrift_IdenticalDistributions(t *testing.T) {
	detector := NewDetector()

	bins := []float64{100, 200, 300, 200, 100}
	res := detector.ComputePSI("credit_score_input", bins, bins)

	if res.Severity != DriftNegligible || res.RetrainingNeeded {
		t.Errorf("expected negligible drift for identical distributions: %+v", res)
	}

	if res.DriftScore > 0.01 {
		t.Errorf("expected PSI close to 0.0, got %f", res.DriftScore)
	}
}

func TestDrift_CriticalShift(t *testing.T) {
	detector := NewDetector()

	baseline := []float64{1000, 800, 500, 200, 50}
	actual := []float64{50, 150, 400, 900, 1200} // Inverted distribution

	res := detector.ComputePSI("applicant_income", baseline, actual)

	if res.Severity != DriftCritical || !res.RetrainingNeeded {
		t.Errorf("expected critical drift with mandatory retraining: %+v", res)
	}

	if res.DriftScore < 0.20 {
		t.Errorf("expected PSI >= 0.20 for inverted distribution, got %f", res.DriftScore)
	}
}

func TestDrift_EvaluateModelDrift(t *testing.T) {
	detector := NewDetector()

	features := map[string]struct{ Baseline, Actual []float64 }{
		"f1_stable": {Baseline: []float64{100, 100}, Actual: []float64{100, 100}},
		"f2_drift":  {Baseline: []float64{1000, 10}, Actual: []float64{10, 1000}},
	}

	report := detector.EvaluateModelDrift("Credit-Risk-Model", features)
	if report.OverallStatus != DriftCritical {
		t.Errorf("expected overall status CRITICAL due to f2_drift")
	}

	if len(report.FeatureDrifts) != 2 {
		t.Errorf("expected 2 feature drift results")
	}
}
