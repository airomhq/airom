package prober

import (
	"testing"
)

func TestQA_AdversarialZeroAndNegativeCounts(t *testing.T) {
	generator := NewGenerator()

	probes := generator.GenerateProbes(-10)
	if len(probes) == 0 {
		t.Fatalf("expected default fallback probe batch for negative count")
	}

	zeroProbes := generator.GenerateProbes(0)
	if len(zeroProbes) == 0 {
		t.Fatalf("expected default fallback probe batch for zero count")
	}
}

func TestQA_AdversarialHugeProbeBatch(t *testing.T) {
	generator := NewGenerator()

	probes := generator.GenerateProbes(1000)
	if len(probes) != 1000 {
		t.Fatalf("expected 1000 probes generated")
	}
}
