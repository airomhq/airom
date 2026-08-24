package tensors

import (
	"math/rand"
	"testing"
)

func TestTensors_CleanNormalDistribution(t *testing.T) {
	detector := NewDetector()

	// 1,000 standard normal weights
	r := rand.New(rand.NewSource(42))
	weights := make([]float32, 1000)
	for i := 0; i < len(weights); i++ {
		weights[i] = float32(r.NormFloat64() * 0.02) // std = 0.02
	}

	header := TensorLayerHeader{
		Name:       "model.layers.0.self_attn.q_proj.weight",
		Format:     FormatSafetensors,
		NumWeights: 1000,
	}

	layers := []LayerData{{Header: header, Weights: weights}}
	result := detector.ScanCheckpoint("clean-model", FormatSafetensors, layers)

	if result.IsPoisoned || len(result.Anomalies) != 0 {
		t.Errorf("expected clean checkpoint, got anomalies: %+v", result.Anomalies)
	}

	if result.IntegrityScore != 100.0 {
		t.Errorf("expected 100.0 integrity score, got %f", result.IntegrityScore)
	}
}

func TestTensors_TrojanBackdoorSpike(t *testing.T) {
	detector := NewDetector()

	r := rand.New(rand.NewSource(42))
	weights := make([]float32, 1000)
	for i := 0; i < len(weights); i++ {
		weights[i] = float32(r.NormFloat64() * 0.01)
	}
	// Inject massive trojan trigger neuron spike
	weights[500] = 50.0

	header := TensorLayerHeader{
		Name:       "model.layers.31.mlp.down_proj.weight",
		Format:     FormatSafetensors,
		NumWeights: 1000,
	}

	anomaly, detected := detector.AnalyzeLayerStatistics(header, weights)
	if !detected {
		t.Fatalf("expected trojan trigger anomaly detected")
	}

	if anomaly.Type != AnomalyTrojanTrigger || anomaly.Severity != "CRITICAL" {
		t.Errorf("unexpected anomaly type/severity: %+v", anomaly)
	}
}

func TestTensors_EntropyCollapse(t *testing.T) {
	detector := NewDetector()

	// Uniform non-zero weights
	weights := make([]float32, 500)
	for i := 0; i < len(weights); i++ {
		weights[i] = 1.0
	}

	header := TensorLayerHeader{Name: "poisoned_layer", Format: FormatGGUF}
	anomaly, detected := detector.AnalyzeLayerStatistics(header, weights)
	if !detected || anomaly.Type != AnomalyEntropyCollapse {
		t.Errorf("expected entropy collapse anomaly detected")
	}
}
