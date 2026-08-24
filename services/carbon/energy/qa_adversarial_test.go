package energy

import (
	"testing"
)

func TestQA_AdversarialZeroTokensAndParams(t *testing.T) {
	profiler := NewProfiler()

	spec := TrainingJobSpec{
		ParameterCount:  0,
		TokenCount:      0,
		NumAccelerators: 0,
	}

	res := profiler.ComputeTrainingEnergy(spec)
	if res.TotalFLOPs != 0 || res.TotalKWh != 0 {
		t.Errorf("expected 0 energy for 0 tokens/params")
	}
}

func TestQA_AdversarialExtremeModelScale(t *testing.T) {
	profiler := NewProfiler()

	// 1,000 Billion (1 Trillion) parameters on 10,000B (10T) tokens on 65,536 B200s
	spec := TrainingJobSpec{
		ModelName:       "Frontier-1T",
		ParameterCount:  1000.0,
		TokenCount:      10000.0,
		Hardware:        GPU_NVIDIA_B200,
		NumAccelerators: 65536,
		PUEFactor:       1.08,
	}

	res := profiler.ComputeTrainingEnergy(spec)
	if res.TotalFLOPs <= 0 || res.TotalMWh <= 0 {
		t.Errorf("failed calculating extreme frontier scale: %+v", res)
	}
}
