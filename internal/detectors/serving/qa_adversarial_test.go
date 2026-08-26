package serving

import (
	"testing"
)

func TestQA_AdversarialNegativeGPUAndModelLen(t *testing.T) {
	detector := NewDetector()

	negCfg := ServingConfigSpec{
		EngineType:         EngineVLLM,
		ModelName:          "neg-model",
		GPUMemoryUtil:      -0.5,
		TensorParallelSize: -2,
		MaxModelLen:        -8192,
	}

	res := detector.EvaluateConfig(negCfg)
	if res.IsConformant {
		t.Fatalf("expected negative configuration values to fail conformance")
	}
}

func TestQA_AdversarialEmptyEngineAndModel(t *testing.T) {
	detector := NewDetector()

	res := detector.EvaluateConfig(ServingConfigSpec{})
	if res.Component == nil {
		t.Fatalf("expected component returned even on empty config")
	}
}
