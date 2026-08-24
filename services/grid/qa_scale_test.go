package grid

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_ExtremeGridScale_100KFiles50Workers(t *testing.T) {
	coord := NewCoordinator()

	const numWorkers = 50
	const numFiles = 100000
	const shardSize = 2000 // 50 partitions

	for i := 0; i < numWorkers; i++ {
		coord.RegisterWorker(&WorkerNode{
			ID:       fmt.Sprintf("worker-%03d", i),
			Role:     RoleScanner,
			Capacity: 2000,
		})
	}

	allFiles := make([]string, numFiles)
	for i := 0; i < numFiles; i++ {
		allFiles[i] = fmt.Sprintf("monorepo/pkg_%d/algo.py", i)
	}

	spec := GridScanSpec{
		JobID:     "mega-scale-job",
		OrgID:     "mega-corp",
		ShardSize: shardSize,
	}

	start := time.Now()
	partitions := coord.PlanPartitions(spec, allFiles)
	if len(partitions) != 50 {
		t.Fatalf("expected 50 partitions, got %d", len(partitions))
	}

	// Submit results in parallel
	var wg sync.WaitGroup
	wg.Add(len(partitions))

	for _, part := range partitions {
		go func(p *PartitionJob) {
			defer wg.Done()
			partInv := &airom.Inventory{
				Components: []airom.Component{
					{
						ID:       airom.ID(fmt.Sprintf("comp_part_%d", p.PartitionID)),
						Kind:     airom.KindHostedLLM,
						Name:     fmt.Sprintf("model-%d", p.PartitionID),
						Provider: airom.KnownString("airom-cloud"),
					},
					{
						ID:       "shared_global_db",
						Kind:     airom.KindVectorDB,
						Name:     "qdrant-enterprise",
						Provider: airom.KnownString("qdrant"),
					},
				},
				Relationships: []airom.Relationship{
					{
						From: airom.ID(fmt.Sprintf("comp_part_%d", p.PartitionID)),
						To:   "shared_global_db",
						Type: airom.RelUses,
					},
				},
			}
			_ = coord.SubmitPartitionResult(spec.JobID, p.PartitionID, partInv)
		}(part)
	}

	wg.Wait()

	masterInv, err := coord.AggregateMasterInventory(context.Background(), spec.JobID)
	if err != nil {
		t.Fatalf("aggregation failed: %v", err)
	}
	duration := time.Since(start)

	// 50 unique models + 1 shared qdrant = 51 components
	if len(masterInv.Components) != 51 {
		t.Errorf("expected 51 components, got %d", len(masterInv.Components))
	}

	filesPerSec := float64(numFiles) / duration.Seconds()
	t.Logf("=== SPRINT 45 SCALE: 100K FILES OVER 50 GRID WORKERS ===")
	t.Logf("Files:      %d", numFiles)
	t.Logf("Partitions: %d", len(partitions))
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f files/sec", filesPerSec)

	if duration > 2*time.Second {
		t.Errorf("expected execution < 2s, took %v", duration)
	}
}

func TestQA_ConcurrentGridStorm_100Workers(t *testing.T) {
	coord := NewCoordinator()
	const numPartitions = 100

	spec := GridScanSpec{
		JobID:     "concurrent-storm-job",
		ShardSize: 10,
	}

	files := make([]string, numPartitions*10)
	for i := 0; i < len(files); i++ {
		files[i] = fmt.Sprintf("f%d.py", i)
	}

	_ = coord.PlanPartitions(spec, files)

	var wg sync.WaitGroup
	wg.Add(numPartitions)
	errCh := make(chan error, numPartitions)

	start := time.Now()
	for i := 0; i < numPartitions; i++ {
		go func(partID int) {
			defer wg.Done()
			inv := &airom.Inventory{
				Components: []airom.Component{
					{ID: airom.ID(fmt.Sprintf("c_%d", partID)), Kind: airom.KindHostedLLM, Name: "m"},
				},
			}
			if err := coord.SubmitPartitionResult(spec.JobID, partID, inv); err != nil {
				errCh <- fmt.Errorf("part %d failed: %w", partID, err)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrency error: %v", err)
	}

	master, err := coord.AggregateMasterInventory(context.Background(), spec.JobID)
	if err != nil || len(master.Components) != numPartitions {
		t.Fatalf("aggregation failed: len=%d, err=%v", len(master.Components), err)
	}

	duration := time.Since(start)
	t.Logf("=== SPRINT 45 CONCURRENCY: %d worker submissions in %v ===", numPartitions, duration)
}

func BenchmarkGrid_Aggregation(b *testing.B) {
	coord := NewCoordinator()
	spec := GridScanSpec{JobID: "bench", ShardSize: 10}
	files := make([]string, 100)
	partitions := coord.PlanPartitions(spec, files)

	for _, p := range partitions {
		_ = coord.SubmitPartitionResult("bench", p.PartitionID, &airom.Inventory{
			Components: []airom.Component{{ID: "c1", Kind: airom.KindHostedLLM, Name: "m"}},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = coord.AggregateMasterInventory(context.Background(), "bench")
	}
}
