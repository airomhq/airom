// Package serving provides discovery and safety evaluation for high-throughput LLM serving
// engines including vLLM, SGLang, TensorRT-LLM, and HuggingFace TGI.
package serving

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// EngineType classifies the high-throughput inference engine.
type EngineType string

const (
	EngineVLLM        EngineType = "VLLM"
	EngineSGLang      EngineType = "SGLANG"
	EngineTensorRTLLM EngineType = "TENSORRT_LLM"
	EngineTGI         EngineType = "HUGGINGFACE_TGI"
)

// ServingConfigSpec models the runtime configuration parameters of an inference engine.
type ServingConfigSpec struct {
	EngineType           EngineType `json:"engineType"`
	ModelName            string     `json:"modelName"`            // e.g. "meta-llama/Meta-Llama-3.1-70B-Instruct"
	TensorParallelSize   int        `json:"tensorParallelSize"`   // e.g. 4 GPUs
	PipelineParallelSize int        `json:"pipelineParallelSize"` // e.g. 1
	GPUMemoryUtil        float64    `json:"gpuMemoryUtil"`        // e.g. 0.90
	MaxModelLen          int        `json:"maxModelLen"`          // e.g. 8192 context window
	SpeculativeModel     string     `json:"speculativeModel,omitempty"`
	KVQuantization       string     `json:"kvQuantization,omitempty"` // "fp8", "int8"
	EnforceEager         bool       `json:"enforceEager"`
	SourceLocation       string     `json:"sourceLocation"`
}

// ServingSafetyVerdict models the safety evaluation outcome for a model serving configuration.
type ServingSafetyVerdict struct {
	EngineType   EngineType       `json:"engineType"`
	ModelName    string           `json:"modelName"`
	IsConformant bool             `json:"isConformant"`
	Violations   []string         `json:"violations"`
	Component    *airom.Component `json:"component"`
	EvaluatedAt  time.Time        `json:"evaluatedAt"`
}
