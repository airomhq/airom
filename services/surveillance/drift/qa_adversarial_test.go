package drift

import (
	"testing"
)

func TestQA_AdversarialMismatchedSliceLengths(t *testing.T) {
	detector := NewDetector()

	res := detector.ComputePSI("mismatch", []float64{1, 2}, []float64{1, 2, 3, 4})
	if res.DriftScore != 0.0 || res.Severity != DriftNegligible {
		t.Errorf("expected negligible on mismatched length")
	}
}

func TestQA_AdversarialZeroTotals(t *testing.T) {
	detector := NewDetector()

	res := detector.ComputePSI("zeros", []float64{0, 0, 0}, []float64{0, 0, 0})
	if res.DriftScore != 0.0 || res.Severity != DriftNegligible {
		t.Errorf("expected 0 drift for zero bins")
	}
}
