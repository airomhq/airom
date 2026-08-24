package tensors

import (
	"fmt"
	"math"
	"time"
)

// LayerData holds a layer's header alongside its weights.
type LayerData struct {
	Header  TensorLayerHeader `json:"header"`
	Weights []float32         `json:"weights"`
}

// Detector performs statistical weight-level neural forensics.
type Detector struct{}

// NewDetector constructs a tensor backdoor detector.
func NewDetector() *Detector {
	return &Detector{}
}

// AnalyzeLayerStatistics scans a layer's float32 weight slice for trojan backdoor signatures.
func (d *Detector) AnalyzeLayerStatistics(layer TensorLayerHeader, weights []float32) (LayerAnomaly, bool) {
	n := len(weights)
	if n < 10 {
		return LayerAnomaly{}, false
	}

	var sum float64
	var maxMag float64
	for _, w := range weights {
		val := float64(w)
		absVal := math.Abs(val)
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return LayerAnomaly{
				LayerName:    layer.Name,
				Type:         AnomalyExtremeOutlier,
				Severity:     "CRITICAL",
				MaxMagnitude: absVal,
				Detail:       "Weight tensor contains NaN or Infinite values",
			}, true
		}
		sum += val
		if absVal > maxMag {
			maxMag = absVal
		}
	}

	mean := sum / float64(n)

	var varSum, kurtSum float64
	for _, w := range weights {
		diff := float64(w) - mean
		varSum += diff * diff
		kurtSum += diff * diff * diff * diff
	}

	variance := varSum / float64(n)
	stdDev := math.Sqrt(variance)

	// Entropy collapse detection
	if variance == 0 && maxMag > 0 {
		return LayerAnomaly{
			LayerName:    layer.Name,
			Type:         AnomalyEntropyCollapse,
			Severity:     "HIGH",
			MaxMagnitude: maxMag,
			Detail:       "Uniform non-zero weight distribution indicative of layer poisoning",
		}, true
	}

	// Kurtosis computation (measure of extreme tails / isolated outlier neurons)
	var kurtosis float64
	if variance > 0 {
		kurtosis = (kurtSum / float64(n)) / (variance * variance)
	}

	// Trojan Backdoor Heuristic: Extreme Kurtosis > 25.0 with max magnitude > 10.0 * stdDev
	if kurtosis > 25.0 && maxMag > 10.0*stdDev && stdDev > 0 {
		return LayerAnomaly{
			LayerName:    layer.Name,
			Type:         AnomalyTrojanTrigger,
			Severity:     "CRITICAL",
			Kurtosis:     kurtosis,
			MaxMagnitude: maxMag,
			Detail:       fmt.Sprintf("Trojan backdoor trigger neuron detected (Kurtosis: %.2f, Max: %.2f)", kurtosis, maxMag),
		}, true
	}

	// Outlier detection: max magnitude > 20.0 * stdDev
	if stdDev > 0 && maxMag > 20.0*stdDev {
		return LayerAnomaly{
			LayerName:    layer.Name,
			Type:         AnomalyExtremeOutlier,
			Severity:     "HIGH",
			Kurtosis:     kurtosis,
			MaxMagnitude: maxMag,
			Detail:       fmt.Sprintf("Extreme outlier weights detected (Max: %.2f vs StdDev: %.2f)", maxMag, stdDev),
		}, true
	}

	return LayerAnomaly{}, false
}

// ScanCheckpoint compiles a full tensor scan result across all model layers.
func (d *Detector) ScanCheckpoint(modelName string, format TensorFormat, layers []LayerData) TensorScanResult {
	result := TensorScanResult{
		ModelName:      modelName,
		Format:         format,
		TotalLayers:    len(layers),
		ScannedAt:      time.Now().UTC(),
		IntegrityScore: 100.0,
	}

	for _, l := range layers {
		result.TotalWeights += int64(len(l.Weights))
		if anomaly, detected := d.AnalyzeLayerStatistics(l.Header, l.Weights); detected {
			result.Anomalies = append(result.Anomalies, anomaly)
			if anomaly.Severity == "CRITICAL" {
				result.IsPoisoned = true
				result.IntegrityScore -= 30.0
			} else {
				result.IntegrityScore -= 10.0
			}
		}
	}

	if result.IntegrityScore < 0.0 {
		result.IntegrityScore = 0.0
	}

	return result
}
