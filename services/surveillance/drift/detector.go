package drift

import (
	"math"
	"time"
)

// Detector computes real-time distribution shifts between baseline and actual inference streams.
type Detector struct{}

// NewDetector constructs a distribution drift detector.
func NewDetector() *Detector {
	return &Detector{}
}

// ComputePSI calculates the Population Stability Index between baseline and actual bin counts.
func (d *Detector) ComputePSI(featureName string, baselineBins, actualBins []float64) FeatureDriftResult {
	if len(baselineBins) == 0 || len(actualBins) == 0 || len(baselineBins) != len(actualBins) {
		return FeatureDriftResult{
			FeatureName: featureName,
			Metric:      MetricPSI,
			DriftScore:  0.0,
			Severity:    DriftNegligible,
		}
	}

	var baseTotal, actTotal float64
	for _, v := range baselineBins {
		baseTotal += v
	}
	for _, v := range actualBins {
		actTotal += v
	}

	if baseTotal == 0 || actTotal == 0 {
		return FeatureDriftResult{FeatureName: featureName, Metric: MetricPSI, Severity: DriftNegligible}
	}

	const eps = 1e-4 // Smoothing epsilon
	var psi float64

	for i := range baselineBins {
		bProp := (baselineBins[i] / baseTotal) + eps
		aProp := (actualBins[i] / actTotal) + eps

		psi += (aProp - bProp) * math.Log(aProp/bProp)
	}

	severity := DriftNegligible
	retrain := false

	if psi >= 0.20 {
		severity = DriftCritical
		retrain = true
	} else if psi >= 0.10 {
		severity = DriftModerate
	}

	return FeatureDriftResult{
		FeatureName:      featureName,
		Metric:           MetricPSI,
		DriftScore:       psi,
		Severity:         severity,
		RetrainingNeeded: retrain,
	}
}

// EvaluateModelDrift evaluates all model features and generates a comprehensive report.
func (d *Detector) EvaluateModelDrift(modelName string, features map[string]struct{ Baseline, Actual []float64 }) ModelDriftReport {
	report := ModelDriftReport{
		ModelName:     modelName,
		TotalFeatures: len(features),
		OverallStatus: DriftNegligible,
		EvaluatedAt:   time.Now().UTC(),
		StatutoryNote: "EU AI Act Article 72 & NIST AI RMF Post-Market Monitoring",
	}

	for name, bins := range features {
		res := d.ComputePSI(name, bins.Baseline, bins.Actual)
		report.FeatureDrifts = append(report.FeatureDrifts, res)

		if res.Severity == DriftCritical {
			report.OverallStatus = DriftCritical
		} else if res.Severity == DriftModerate && report.OverallStatus != DriftCritical {
			report.OverallStatus = DriftModerate
		}
	}

	return report
}
