// Package energy implements hardware-level GPU FLOPs and electrical energy modeling for AI workloads
// pursuant to EU AI Act Article 53 and California SB 219 (ARCHITECTURE.md §16).
package energy

import (
	"time"
)

// AcceleratorType classifies the GPU/TPU architecture used for computation.
type AcceleratorType string

const (
	GPU_NVIDIA_H100 AcceleratorType = "nvidia_h100_sxm"
	GPU_NVIDIA_A100 AcceleratorType = "nvidia_a100_80gb"
	GPU_NVIDIA_B200 AcceleratorType = "nvidia_b200_blackwell"
	GPU_AMD_MI300X  AcceleratorType = "amd_mi300x"
	TPU_GOOGLE_V5E  AcceleratorType = "google_tpu_v5e"
)

// HardwareSpec defines the power and thermal characteristics of an accelerator.
type HardwareSpec struct {
	Type       AcceleratorType `json:"type"`
	TDPWatts   float64         `json:"tdpWatts"`
	PeakTFLOPS float64         `json:"peakTflops"` // FP16/BF16
	DefaultPUE float64         `json:"defaultPue"` // Power Usage Effectiveness (e.g. 1.15)
}

// TrainingJobSpec defines the compute parameters for a training or fine-tuning run.
type TrainingJobSpec struct {
	ModelName       string          `json:"modelName"`
	ParameterCount  float64         `json:"parameterCount"` // in billions (e.g. 70.0)
	TokenCount      float64         `json:"tokenCount"`     // in billions (e.g. 2000.0)
	Hardware        AcceleratorType `json:"hardware"`
	NumAccelerators int             `json:"numAccelerators"`
	PUEFactor       float64         `json:"pueFactor"` // Data center PUE
}

// EnergyAccounting captures the computed energy consumption.
type EnergyAccounting struct {
	TotalFLOPs     float64         `json:"totalFlops"`     // Floating point operations
	TotalKWh       float64         `json:"totalKwh"`       // Kilowatt-hours (including PUE)
	TotalMWh       float64         `json:"totalMwh"`       // Megawatt-hours
	EstimatedHours float64         `json:"estimatedHours"` // Run duration
	HardwareType   AcceleratorType `json:"hardwareType"`
	CalculatedAt   time.Time       `json:"calculatedAt"`
}
