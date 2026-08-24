package tensors

import (
	"math"
	"testing"
)

func TestQA_AdversarialNaNAndInfinityTensors(t *testing.T) {
	detector := NewDetector()

	header := TensorLayerHeader{Name: "corrupt_layer"}

	// NaN test
	weightsNaN := []float32{0.1, 0.2, float32(math.NaN()), 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9}
	anomaly1, detected1 := detector.AnalyzeLayerStatistics(header, weightsNaN)
	if !detected1 || anomaly1.Severity != "CRITICAL" {
		t.Errorf("expected critical detection on NaN tensor")
	}

	// Infinity test
	weightsInf := []float32{0.1, 0.2, float32(math.Inf(1)), 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9}
	anomaly2, detected2 := detector.AnalyzeLayerStatistics(header, weightsInf)
	if !detected2 || anomaly2.Severity != "CRITICAL" {
		t.Errorf("expected critical detection on Inf tensor")
	}
}

func TestQA_AdversarialZeroWeightsAndNilSlices(t *testing.T) {
	detector := NewDetector()

	header := TensorLayerHeader{Name: "empty"}

	_, detected := detector.AnalyzeLayerStatistics(header, nil)
	if detected {
		t.Errorf("nil slice should not trigger false detection")
	}

	_, detected = detector.AnalyzeLayerStatistics(header, []float32{})
	if detected {
		t.Errorf("empty slice should not trigger false detection")
	}
}
