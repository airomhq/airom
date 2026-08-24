// Package drift implements real-time concept and covariate drift detection for deployed AI models
// pursuant to EU AI Act Article 72 (Post-Market Monitoring) (ARCHITECTURE.md §16).
package drift

import (
	"time"
)

// DriftMetric identifies the statistical distance algorithm used.
type DriftMetric string

const (
	MetricPSI          DriftMetric = "population_stability_index_psi"
	MetricWasserstein  DriftMetric = "wasserstein_distance"
	MetricKLDivergence DriftMetric = "kl_divergence"
)

// DriftSeverity categorizes the operational and regulatory impact of distribution shift.
type DriftSeverity string

const (
	DriftNegligible DriftSeverity = "NEGLIGIBLE" // PSI < 0.10
	DriftModerate   DriftSeverity = "MODERATE"   // 0.10 <= PSI < 0.20 (Monitoring advised)
	DriftCritical   DriftSeverity = "CRITICAL"   // PSI >= 0.20 (Mandatory retraining / Article 72 notice)
)

// FeatureDriftResult details distribution shift for a specific model input or output feature.
type FeatureDriftResult struct {
	FeatureName      string        `json:"featureName"`
	Metric           DriftMetric   `json:"metric"`
	DriftScore       float64       `json:"driftScore"`
	Severity         DriftSeverity `json:"severity"`
	RetrainingNeeded bool          `json:"retrainingNeeded"`
}

// ModelDriftReport aggregates real-time drift telemetry across all monitored features.
type ModelDriftReport struct {
	ModelName     string               `json:"modelName"`
	TotalFeatures int                  `json:"totalFeatures"`
	OverallStatus DriftSeverity        `json:"overallStatus"`
	FeatureDrifts []FeatureDriftResult `json:"featureDrifts"`
	StatutoryNote string               `json:"statutoryNote"`
	EvaluatedAt   time.Time            `json:"evaluatedAt"`
}
