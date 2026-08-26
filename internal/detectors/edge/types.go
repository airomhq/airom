// Package edge evaluates edge NPU, TensorRT, and ONNX runtime bindings
// for zero-copy DMA memory boundaries, buffer isolation, and deterministic execution deadlines.
package edge

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// TargetPlatform identifies the edge embedded NPU architecture.
type TargetPlatform string

const (
	PlatformTensorRT    TargetPlatform = "NVIDIA_TENSORRT"
	PlatformAppleANE    TargetPlatform = "APPLE_NEURAL_ENGINE"
	PlatformQualcommNPU TargetPlatform = "QUALCOMM_HEXAGON_NPU"
	PlatformIntelVPU    TargetPlatform = "INTEL_OPENVINO"
	PlatformEdgeTPU     TargetPlatform = "GOOGLE_CORAL_EDGETPU"
)

// MemoryBoundarySpec defines hardware SRAM and DMA buffer safety constraints.
type MemoryBoundarySpec struct {
	MaxSRAMUsageBytes       int64 `json:"maxSramUsageBytes"`       // e.g. 16MB on-chip SRAM limit
	SharedDMABoundaryBytes  int64 `json:"sharedDmaBoundaryBytes"`  // e.g. 128MB shared buffer
	ZeroCopyVerified        bool  `json:"zeroCopyVerified"`        // Memory bounds checked for zero-copy DMA
	DeterministicDeadlineMs int   `json:"deterministicDeadlineMs"` // Hard real-time inference deadline (e.g. 20ms)
}

// EdgeModelBinding represents a compiled edge AI execution plan.
type EdgeModelBinding struct {
	ModelName          string             `json:"modelName"` // e.g. "yolov8n-tensorrt.engine"
	Platform           TargetPlatform     `json:"platform"`
	Quantization       string             `json:"quantization"` // e.g. "INT8_PTQ", "FP16"
	MemorySpec         MemoryBoundarySpec `json:"memorySpec"`
	HasRingBufferGuard bool               `json:"hasRingBufferGuard"` // Protects against DMA buffer overruns
	SourceFile         string             `json:"sourceFile"`
}

// EdgeVerificationResult contains the safety verdict for an edge NPU deployment.
type EdgeVerificationResult struct {
	ModelName   string           `json:"modelName"`
	Platform    TargetPlatform   `json:"platform"`
	IsSafe      bool             `json:"isSafe"`
	Violations  []string         `json:"violations"`
	Component   *airom.Component `json:"component"`
	EvaluatedAt time.Time        `json:"evaluatedAt"`
}
