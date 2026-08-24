package ai

import (
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer/spdx3"
	"github.com/airomhq/airom/pkg/airom"
)

func TestAIProfile_Translation(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/test")
	translator := NewTranslator(serializer)

	creationInfo := &spdx3.CreationInfo{
		SpecVersion: spdx3.SpecVersion,
		Created:     time.Now().UTC(),
		CreatedBy:   []string{"https://spdx.org/spdxdocs/test/agent/airom"},
	}

	comp := &airom.Component{
		ID:       "airom:llama_3_8b",
		Kind:     airom.KindLocalModelFile,
		Name:     "Meta-Llama-3-8B-Instruct.Q4_K_M.gguf",
		Provider: airom.KnownString("meta-llama"),
		Version:  airom.KnownString("3.0"),
		PURL:     "pkg:generic/llama-3-8b@3.0",
		Hashes: []airom.Hash{
			{Alg: "SHA-256", Hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		},
		Model: &airom.ModelFacet{
			Architecture:  airom.KnownString("llama"),
			ParamCount:    airom.KnownInt64(8030000000),
			Quantization:  airom.KnownString("Q4_K_M"),
			ContextLength: airom.KnownInt64(8192),
			Task:          airom.KnownString("text-generation"),
			GenerationParams: []airom.BoundParam{
				{
					Name:  "temperature",
					Value: "0.7",
					Occurrence: &airom.Occurrence{
						Location: airom.Location{Path: "src/generate.py", Line: 42},
					},
				},
				{
					Name:  "top_p",
					Value: "0.9",
				},
			},
			Card: &airom.ModelCard{
				Considerations: &airom.Considerations{
					Users:                []string{"Enterprise Developers"},
					UseCases:             []string{"Code Completion", "RAG Q&A"},
					TechnicalLimitations: []string{"Do not use for medical diagnosis"},
				},
				Energy: []airom.EnergyConsumption{
					{Activity: "inference", KWh: 0.045},
					{Activity: "training", KWh: 12500.0},
				},
			},
		},
	}

	aiModel, _ := translator.TranslateModel(comp, creationInfo)
	if aiModel == nil {
		t.Fatalf("expected non-nil AIModel")
	}

	if aiModel.ModelArchitecture != "llama" {
		t.Errorf("expected architecture llama, got %s", aiModel.ModelArchitecture)
	}
	if aiModel.ParameterCount != 8030000000 {
		t.Errorf("expected param count 8030000000, got %d", aiModel.ParameterCount)
	}
	if aiModel.Quantization != "Q4_K_M" {
		t.Errorf("expected Q4_K_M, got %s", aiModel.Quantization)
	}
	if aiModel.ContextWindow != 8192 {
		t.Errorf("expected context 8192, got %d", aiModel.ContextWindow)
	}

	if len(aiModel.Hyperparameters) != 2 {
		t.Fatalf("expected 2 hyperparameters, got %d", len(aiModel.Hyperparameters))
	}
	if aiModel.Hyperparameters[0].ParameterKey != "temperature" || aiModel.Hyperparameters[0].ContextLine != 42 {
		t.Errorf("hyperparameter 0 mismatch: %+v", aiModel.Hyperparameters[0])
	}

	if aiModel.SafetyLimits == nil || len(aiModel.SafetyLimits.UseCases) != 2 {
		t.Fatalf("safety limits mismatch: %+v", aiModel.SafetyLimits)
	}

	if len(aiModel.EnergyMetrics) != 2 {
		t.Fatalf("expected 2 energy metrics, got %d", len(aiModel.EnergyMetrics))
	}
}

func TestAIProfile_SparseModel(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/test")
	translator := NewTranslator(serializer)

	comp := &airom.Component{
		ID:   "airom:sparse",
		Kind: airom.KindHostedLLM,
		Name: "gpt-4",
	}

	aiModel, _ := translator.TranslateModel(comp, &spdx3.CreationInfo{})
	if aiModel == nil {
		t.Fatalf("expected non-nil AIModel")
	}
	if aiModel.PackageVersion != spdx3.NoAssertion {
		t.Errorf("expected NOASSERTION packageVersion, got %s", aiModel.PackageVersion)
	}
}
