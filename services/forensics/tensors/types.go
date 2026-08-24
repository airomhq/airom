// Package tensors implements weight-level neural forensics and trojan backdoor detection
// in model checkpoints (ARCHITECTURE.md §16).
package tensors

import (
	"time"
)

// TensorFormat identifies the model checkpoint storage format.
type TensorFormat string

const (
	FormatSafetensors TensorFormat = "safetensors"
	FormatGGUF        TensorFormat = "gguf"
	FormatPyTorch     TensorFormat = "pytorch_bin"
	FormatONNX        TensorFormat = "onnx"
)

// AnomalyType classifies the structural/statistical anomaly identified in weights.
type AnomalyType string

const (
	AnomalyTrojanTrigger    AnomalyType = "trojan_trigger_neuron"   // Abnormal high-magnitude activation cluster
	AnomalySpectralSignFlip AnomalyType = "spectral_sign_flip"      // Adversarial sign perturbations
	AnomalyExtremeOutlier   AnomalyType = "extreme_weight_outliers" // Spurious extreme magnitudes
	AnomalyEntropyCollapse  AnomalyType = "weight_entropy_collapse" // Degenerate/poisoned uniform layers
)

// TensorLayerHeader contains metadata about a specific weight layer.
type TensorLayerHeader struct {
	Name       string       `json:"name"`
	Shape      []int64      `json:"shape"`
	DType      string       `json:"dtype"` // F32, F16, BF16, Q4_K
	Format     TensorFormat `json:"format"`
	NumWeights int64        `json:"numWeights"`
}

// LayerAnomaly records an identified statistical anomaly in a weight tensor.
type LayerAnomaly struct {
	LayerName    string      `json:"layerName"`
	Type         AnomalyType `json:"type"`
	Severity     string      `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW
	Kurtosis     float64     `json:"kurtosis"`
	MaxMagnitude float64     `json:"maxMagnitude"`
	Detail       string      `json:"detail"`
}

// TensorScanResult summarizes the forensic analysis of a model checkpoint.
type TensorScanResult struct {
	ModelName      string         `json:"modelName"`
	Format         TensorFormat   `json:"format"`
	TotalLayers    int            `json:"totalLayers"`
	TotalWeights   int64          `json:"totalWeights"`
	Anomalies      []LayerAnomaly `json:"anomalies"`
	IsPoisoned     bool           `json:"isPoisoned"`
	IntegrityScore float64        `json:"integrityScore"` // 0.0 - 100.0 (100 = clean)
	ScannedAt      time.Time      `json:"scannedAt"`
}
