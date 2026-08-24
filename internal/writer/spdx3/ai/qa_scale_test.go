package ai

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer/spdx3"
	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_ExtremeAIProfileScale_50KModels(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/scale")
	translator := NewTranslator(serializer)
	creationInfo := &spdx3.CreationInfo{SpecVersion: spdx3.SpecVersion, Created: time.Now().UTC()}

	const numModels = 50000
	models := make([]*airom.Component, numModels)
	for i := 0; i < numModels; i++ {
		models[i] = &airom.Component{
			ID:       airom.ID(fmt.Sprintf("airom:model_%06d", i)),
			Kind:     airom.KindHostedLLM,
			Name:     fmt.Sprintf("enterprise-model-%d", i),
			Provider: airom.KnownString("airom-cloud"),
			Version:  airom.KnownString("1.0.0"),
			Model: &airom.ModelFacet{
				Architecture:  airom.KnownString("transformer"),
				ParamCount:    airom.KnownInt64(70000000000),
				Quantization:  airom.KnownString("int8"),
				ContextLength: airom.KnownInt64(32768),
				GenerationParams: []airom.BoundParam{
					{Name: "temperature", Value: "0.2"},
					{Name: "max_tokens", Value: "4096"},
				},
				Card: &airom.ModelCard{
					Considerations: &airom.Considerations{UseCases: []string{"Compliance Audit"}},
					Energy:         []airom.EnergyConsumption{{Activity: "inference", KWh: 0.02}},
				},
			},
		}
	}

	start := time.Now()
	for i := 0; i < numModels; i++ {
		m, _ := translator.TranslateModel(models[i], creationInfo)
		if m == nil {
			t.Fatalf("nil model at index %d", i)
		}
	}
	duration := time.Since(start)

	modelsPerSec := float64(numModels) / duration.Seconds()
	t.Logf("=== SPRINT 32 SCALE: 50K SPDX 3.0.1 AI MODELS ===")
	t.Logf("Models:     %d", numModels)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f models/sec", modelsPerSec)

	if duration > 2*time.Second {
		t.Errorf("expected translation < 2s, took %v", duration)
	}
}

func TestQA_ConcurrentAIProfileStorm_100Workers(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/concurrent")
	translator := NewTranslator(serializer)
	creationInfo := &spdx3.CreationInfo{SpecVersion: spdx3.SpecVersion, Created: time.Now().UTC()}

	comp := &airom.Component{
		ID:       "airom:c1",
		Kind:     airom.KindHostedLLM,
		Name:     "gpt-4o",
		Provider: airom.KnownString("openai"),
		Model: &airom.ModelFacet{
			Architecture: airom.KnownString("gpt4"),
			ParamCount:   airom.KnownInt64(1800000000000),
		},
	}

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m, _ := translator.TranslateModel(comp, creationInfo)
				if m == nil || m.ParameterCount != 1800000000000 {
					errCh <- fmt.Errorf("worker %d iter %d invalid model", workerID, j)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrency error: %v", err)
	}

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 32 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkAIProfile_10KModels(b *testing.B) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/bench")
	translator := NewTranslator(serializer)
	creationInfo := &spdx3.CreationInfo{SpecVersion: spdx3.SpecVersion, Created: time.Now().UTC()}

	comp := &airom.Component{
		ID:       "airom:c1",
		Kind:     airom.KindHostedLLM,
		Name:     "gpt-4o",
		Provider: airom.KnownString("openai"),
		Model: &airom.ModelFacet{
			Architecture: airom.KnownString("gpt4"),
			ParamCount:   airom.KnownInt64(1800000000000),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = translator.TranslateModel(comp, creationInfo)
	}
}
