package ociregistry

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeOCIScale_10KPackPull(t *testing.T) {
	client := NewClient(RegistryConfig{})

	meta := RuleBundleMeta{Name: "scale-pack", Version: "v1.0.0"}
	rules := map[string][]byte{
		"rules/rule1.yaml": []byte("id: rule1\npattern: gpt-4o"),
		"rules/rule2.yaml": []byte("id: rule2\npattern: claude-3-5"),
	}

	layerBytes, manifestBytes, err := PackRules(meta, rules)
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}

	const numPacks = 10000
	start := time.Now()

	for i := 0; i < numPacks; i++ {
		tag := fmt.Sprintf("ghcr.io/org/rules:v%d", i)
		if err := client.Push(context.Background(), tag, layerBytes, manifestBytes); err != nil {
			t.Fatalf("push failed at %d: %v", i, err)
		}
		pulled, _, err := client.Pull(context.Background(), tag)
		if err != nil || len(pulled) != 2 {
			t.Fatalf("pull failed at %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numPacks*2) / duration.Seconds()
	t.Logf("=== SPRINT 39 SCALE: 10K OCI RULE PACK PUSH/PULL OPS ===")
	t.Logf("Packs:      %d", numPacks)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f ops/sec", opsPerSec)

	if duration > 2*time.Second {
		t.Errorf("expected execution < 2s, took %v", duration)
	}
}

func TestQA_ConcurrentOCIStorm_100Workers(t *testing.T) {
	client := NewClient(RegistryConfig{})

	meta := RuleBundleMeta{Name: "concurrent-pack", Version: "v1.0.0"}
	rules := map[string][]byte{"rules/r.yaml": []byte("id: r\npattern: test")}
	layerBytes, manifestBytes, _ := PackRules(meta, rules)

	const numWorkers = 100
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				tag := fmt.Sprintf("ghcr.io/test/pack-%d-%d", workerID, j)
				if err := client.Push(context.Background(), tag, layerBytes, manifestBytes); err != nil {
					errCh <- fmt.Errorf("push error %d-%d: %w", workerID, j, err)
					return
				}
				pulled, _, err := client.Pull(context.Background(), tag)
				if err != nil || len(pulled) == 0 {
					errCh <- fmt.Errorf("pull error %d-%d: %w", workerID, j, err)
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

	totalOps := numWorkers * iterations * 2
	duration := time.Since(start)
	t.Logf("=== SPRINT 39 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkOCI_PushPull(b *testing.B) {
	client := NewClient(RegistryConfig{})
	meta := RuleBundleMeta{Name: "bench-pack", Version: "v1.0"}
	rules := map[string][]byte{"r.yaml": []byte("id: r")}
	layerBytes, manifestBytes, _ := PackRules(meta, rules)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tag := fmt.Sprintf("ghcr.io/bench/tag-%d", i)
		_ = client.Push(context.Background(), tag, layerBytes, manifestBytes)
		_, _, _ = client.Pull(context.Background(), tag)
	}
}
