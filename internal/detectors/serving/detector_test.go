package serving

import (
	"testing"
)

func TestServing_CompliantVLLMPasses(t *testing.T) {
	detector := NewDetector()

	cfg := ServingConfigSpec{
		EngineType:         EngineVLLM,
		ModelName:          "meta-llama/Meta-Llama-3.1-70B-Instruct",
		TensorParallelSize: 4,
		GPUMemoryUtil:      0.90,
		MaxModelLen:        32768,
		KVQuantization:     "fp8",
	}

	res := detector.EvaluateConfig(cfg)
	if !res.IsConformant || len(res.Violations) != 0 {
		t.Fatalf("expected conformant serving config, got violations: %+v", res.Violations)
	}

	if res.Component == nil || res.Component.Name != "meta-llama/Meta-Llama-3.1-70B-Instruct" {
		t.Errorf("unexpected component: %+v", res.Component)
	}
}

func TestServing_OOMRiskFails(t *testing.T) {
	detector := NewDetector()

	unsafeCfg := ServingConfigSpec{
		EngineType:         EngineSGLang,
		ModelName:          "mistralai/Mistral-Large-Instruct-2407",
		TensorParallelSize: 0,      // Invalid TP size
		GPUMemoryUtil:      0.99,   // Dangerous >0.95 OOM
		MaxModelLen:        262144, // 256k without KV quant
	}

	res := detector.EvaluateConfig(unsafeCfg)
	if res.IsConformant || len(res.Violations) < 3 {
		t.Fatalf("expected unsafe serving config to fail with at least 3 violations, got %d", len(res.Violations))
	}
}
