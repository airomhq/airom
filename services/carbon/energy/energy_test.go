package energy

import (
	"testing"
)

func TestEnergy_ComputeTrainingEnergy_Llama70B(t *testing.T) {
	profiler := NewProfiler()

	spec := TrainingJobSpec{
		ModelName:       "Llama-3-70B-Simulated",
		ParameterCount:  70.0,   // 70B
		TokenCount:      2000.0, // 2T tokens
		Hardware:        GPU_NVIDIA_H100,
		NumAccelerators: 1024,
		PUEFactor:       1.15,
	}

	result := profiler.ComputeTrainingEnergy(spec)

	// 6 * 70e9 * 2000e9 = 8.4e23 FLOPs
	expectedFLOPs := 8.4e23
	if result.TotalFLOPs != expectedFLOPs {
		t.Errorf("expected %e FLOPs, got %e", expectedFLOPs, result.TotalFLOPs)
	}

	if result.TotalMWh <= 0 || result.EstimatedHours <= 0 {
		t.Errorf("invalid energy calculation: %+v", result)
	}
}

func TestEnergy_HardwareFallback(t *testing.T) {
	profiler := NewProfiler()

	spec := TrainingJobSpec{
		ModelName:       "Custom-7B",
		ParameterCount:  7.0,
		TokenCount:      100.0,
		Hardware:        "unknown_hardware",
		NumAccelerators: 8,
	}

	result := profiler.ComputeTrainingEnergy(spec)
	if result.TotalKWh <= 0 {
		t.Errorf("expected positive kWh calculation")
	}
}
