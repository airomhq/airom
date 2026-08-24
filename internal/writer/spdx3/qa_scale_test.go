package spdx3

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_ExtremeSPDX3Scale_100KElements(t *testing.T) {
	w := New(writer.Options{})

	const numComps = 50000
	const numRels = 50000

	comps := make([]airom.Component, numComps)
	for i := 0; i < numComps; i++ {
		comps[i] = airom.Component{
			ID:       airom.ID(fmt.Sprintf("airom:comp_%06d", i)),
			Kind:     airom.KindHostedLLM,
			Name:     fmt.Sprintf("model-service-%d", i),
			Provider: airom.KnownString("enterprise-ai"),
			Version:  airom.KnownString("v1.0.0"),
			PURL:     fmt.Sprintf("pkg:generic/model-%d@1.0.0", i),
		}
	}

	rels := make([]airom.Relationship, numRels)
	for i := 0; i < numRels; i++ {
		targetIdx := (i + 1) % numComps
		rels[i] = airom.Relationship{
			From: comps[i].ID,
			To:   comps[targetIdx].ID,
			Type: airom.RelDependsOn,
		}
	}

	inv := &airom.Inventory{
		Timestamp:     time.Now().UTC(),
		Tool:          airom.ToolInfo{Name: "airom", Version: "1.0.0"},
		Source:        airom.SourceInfo{Kind: "dir", Target: "scale-test-100k"},
		Components:    comps,
		Relationships: rels,
	}

	start := time.Now()
	var buf bytes.Buffer
	buf.Grow(50 * 1024 * 1024) // 50MB pre-allocation

	if err := w.Write(&buf, inv); err != nil {
		t.Fatalf("failed to write 100K SPDX 3 elements: %v", err)
	}
	duration := time.Since(start)

	totalElements := numComps + numRels + 2 // + Agent + SpdxDocument
	elemPerSec := float64(totalElements) / duration.Seconds()

	t.Logf("=== SPRINT 31 SCALE: 100K SPDX 3.0.1 ELEMENTS ===")
	t.Logf("Elements:   %d", totalElements)
	t.Logf("Output:     %.2f MB", float64(buf.Len())/(1024*1024))
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f elements/sec", elemPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected serialization < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentSPDX3Storm_100Workers(t *testing.T) {
	w := New(writer.Options{})
	const numWorkers = 100
	const iterationsPerWorker = 20

	inv := &airom.Inventory{
		Timestamp: time.Now().UTC(),
		Tool:      airom.ToolInfo{Name: "airom", Version: "1.0.0"},
		Source:    airom.SourceInfo{Kind: "dir", Target: "concurrent-storm"},
		Components: []airom.Component{
			{ID: "airom:c1", Kind: airom.KindHostedLLM, Name: "claude-3-5", Provider: airom.KnownString("anthropic")},
			{ID: "airom:c2", Kind: airom.KindFramework, Name: "langchain", Provider: airom.KnownString("langchain-ai")},
		},
		Relationships: []airom.Relationship{
			{From: "airom:c2", To: "airom:c1", Type: airom.RelDependsOn},
		},
	}

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers*iterationsPerWorker)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterationsPerWorker; j++ {
				var buf bytes.Buffer
				if err := w.Write(&buf, inv); err != nil {
					errCh <- fmt.Errorf("worker %d iter %d: %w", workerID, j, err)
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

	totalRuns := numWorkers * iterationsPerWorker
	duration := time.Since(start)
	t.Logf("=== SPRINT 31 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterationsPerWorker)
	t.Logf("Completed:  %d docs in %v (%.2f docs/sec)", totalRuns, duration, float64(totalRuns)/duration.Seconds())
}

func BenchmarkSPDX3_10KElements(b *testing.B) {
	w := New(writer.Options{})
	comps := make([]airom.Component, 5000)
	for i := 0; i < 5000; i++ {
		comps[i] = airom.Component{
			ID:       airom.ID(fmt.Sprintf("airom:comp_%d", i)),
			Kind:     airom.KindHostedLLM,
			Name:     fmt.Sprintf("model-%d", i),
			Provider: airom.KnownString("bench"),
		}
	}
	inv := &airom.Inventory{
		Timestamp:  time.Now().UTC(),
		Tool:       airom.ToolInfo{Name: "airom", Version: "1.0.0"},
		Source:     airom.SourceInfo{Kind: "dir", Target: "bench"},
		Components: comps,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		_ = w.Write(&buf, inv)
	}
}
