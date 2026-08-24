package dataset

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer/spdx3"
	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_ExtremeDatasetScale_50KDatasets(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/scale-ds")
	translator := NewTranslator(serializer)
	creationInfo := &spdx3.CreationInfo{SpecVersion: spdx3.SpecVersion, Created: time.Now().UTC()}

	const numDatasets = 50000
	datasets := make([]*airom.Component, numDatasets)
	for i := 0; i < numDatasets; i++ {
		datasets[i] = &airom.Component{
			ID:       airom.ID(fmt.Sprintf("airom:ds_%06d", i)),
			Kind:     airom.KindDataset,
			Name:     fmt.Sprintf("enterprise-corpus-%d", i),
			Provider: airom.KnownString("airom-data"),
			Version:  airom.KnownString("1.0.0"),
			PURL:     fmt.Sprintf("pkg:generic/corpus-%d@1.0.0", i),
			Data: &airom.DataFacet{
				Format:    airom.KnownString("parquet"),
				SizeBytes: airom.KnownInt64(1024 * 1024 * 1024),
				URL:       airom.KnownString(fmt.Sprintf("https://data.airom.internal/corpus-%d.parquet", i)),
			},
		}
	}

	start := time.Now()
	for i := 0; i < numDatasets; i++ {
		ds, _ := translator.TranslateDataset(datasets[i], creationInfo)
		if ds == nil {
			t.Fatalf("nil dataset at index %d", i)
		}
	}
	duration := time.Since(start)

	dsPerSec := float64(numDatasets) / duration.Seconds()
	t.Logf("=== SPRINT 33 SCALE: 50K SPDX 3.0.1 DATASETS ===")
	t.Logf("Datasets:   %d", numDatasets)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f datasets/sec", dsPerSec)

	if duration > 2*time.Second {
		t.Errorf("expected translation < 2s, took %v", duration)
	}
}

func TestQA_ConcurrentDatasetStorm_100Workers(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/concurrent-ds")
	translator := NewTranslator(serializer)
	creationInfo := &spdx3.CreationInfo{SpecVersion: spdx3.SpecVersion, Created: time.Now().UTC()}

	comp := &airom.Component{
		ID:       "airom:ds1",
		Kind:     airom.KindDataset,
		Name:     "fine-tuning-corpus",
		Provider: airom.KnownString("data-corp"),
		Data: &airom.DataFacet{
			Format:    airom.KnownString("jsonl"),
			SizeBytes: airom.KnownInt64(500000000),
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
				ds, _ := translator.TranslateDataset(comp, creationInfo)
				if ds == nil || ds.SizeBytes != 500000000 {
					errCh <- fmt.Errorf("worker %d iter %d invalid dataset", workerID, j)
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
	t.Logf("=== SPRINT 33 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkDataset_10KDatasets(b *testing.B) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/bench-ds")
	translator := NewTranslator(serializer)
	creationInfo := &spdx3.CreationInfo{SpecVersion: spdx3.SpecVersion, Created: time.Now().UTC()}

	comp := &airom.Component{
		ID:       "airom:ds1",
		Kind:     airom.KindDataset,
		Name:     "benchmark-dataset",
		Provider: airom.KnownString("bench"),
		Data: &airom.DataFacet{
			Format:    airom.KnownString("parquet"),
			SizeBytes: airom.KnownInt64(1000000),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = translator.TranslateDataset(comp, creationInfo)
	}
}
