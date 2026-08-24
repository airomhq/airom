package energy

import (
	"time"
)

// Profiler computes energy consumption from model parameters and hardware specifications.
type Profiler struct {
	hardwareCatalog map[AcceleratorType]HardwareSpec
}

// NewProfiler constructs an AI energy profiler.
func NewProfiler() *Profiler {
	catalog := map[AcceleratorType]HardwareSpec{
		GPU_NVIDIA_H100: {Type: GPU_NVIDIA_H100, TDPWatts: 700.0, PeakTFLOPS: 1979.0, DefaultPUE: 1.15},
		GPU_NVIDIA_A100: {Type: GPU_NVIDIA_A100, TDPWatts: 400.0, PeakTFLOPS: 312.0, DefaultPUE: 1.20},
		GPU_NVIDIA_B200: {Type: GPU_NVIDIA_B200, TDPWatts: 1000.0, PeakTFLOPS: 4500.0, DefaultPUE: 1.10},
		GPU_AMD_MI300X:  {Type: GPU_AMD_MI300X, TDPWatts: 750.0, PeakTFLOPS: 1300.0, DefaultPUE: 1.15},
		TPU_GOOGLE_V5E:  {Type: TPU_GOOGLE_V5E, TDPWatts: 250.0, PeakTFLOPS: 197.0, DefaultPUE: 1.10},
	}
	return &Profiler{hardwareCatalog: catalog}
}

// ComputeTrainingEnergy calculates total FLOPs and energy (kWh) for training.
func (p *Profiler) ComputeTrainingEnergy(spec TrainingJobSpec) EnergyAccounting {
	specPUE := spec.PUEFactor
	if specPUE <= 0 {
		specPUE = 1.15
	}

	hw, ok := p.hardwareCatalog[spec.Hardware]
	if !ok {
		hw = p.hardwareCatalog[GPU_NVIDIA_H100]
	}

	// Total Training FLOPs = 6 * Parameters * Tokens (Kaplan et al. / Chinchilla scaling law)
	// Parameters in Billions (1e9), Tokens in Billions (1e9)
	totalFLOPs := 6.0 * (spec.ParameterCount * 1e9) * (spec.TokenCount * 1e9)

	// Model Flops Utilization (MFU) baseline ~ 40%
	const mfu = 0.40
	effectiveTFLOPS := hw.PeakTFLOPS * mfu * 1e12 // ops per second per GPU

	numGPUs := float64(spec.NumAccelerators)
	if numGPUs <= 0 {
		numGPUs = 8.0
	}

	clusterThroughput := effectiveTFLOPS * numGPUs
	seconds := totalFLOPs / clusterThroughput
	hours := seconds / 3600.0

	// Electrical Power = (NumGPUs * TDP_Watts) * PUE
	totalWatts := (numGPUs * hw.TDPWatts) * specPUE
	totalKWh := (totalWatts * hours) / 1000.0
	totalMWh := totalKWh / 1000.0

	return EnergyAccounting{
		TotalFLOPs:     totalFLOPs,
		TotalKWh:       totalKWh,
		TotalMWh:       totalMWh,
		EstimatedHours: hours,
		HardwareType:   spec.Hardware,
		CalculatedAt:   time.Now().UTC(),
	}
}
