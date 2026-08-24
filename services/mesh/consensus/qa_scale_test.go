package consensus

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeLedgerScale_10KBlocks(t *testing.T) {
	ledger := NewLedger()

	const numBlocks = 10000
	events := []string{"COMPLIANCE_SNAPSHOT_RECORDED", "JURISDICTION_CO_SB_24_205_MET"}

	start := time.Now()
	for i := 0; i < numBlocks; i++ {
		_, err := ledger.AppendBlock("cluster-prod", "signer-node", events)
		if err != nil {
			t.Fatalf("failed at append %d: %v", i, err)
		}
	}
	appendDuration := time.Since(start)

	validateStart := time.Now()
	err := ledger.ValidateChain()
	if err != nil {
		t.Fatalf("chain validation failed: %v", err)
	}
	validateDuration := time.Since(validateStart)

	totalDuration := appendDuration + validateDuration
	blocksPerSec := float64(numBlocks) / totalDuration.Seconds()
	t.Logf("=== SPRINT 54 SCALE: 10K REPLICATED COMPLIANCE LEDGER BLOCKS ===")
	t.Logf("Blocks:          %d", numBlocks)
	t.Logf("Append Time:     %v", appendDuration)
	t.Logf("Validation Time: %v", validateDuration)
	t.Logf("Total Time:      %v", totalDuration)
	t.Logf("Throughput:      %.2f blocks/sec", blocksPerSec)

	if totalDuration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", totalDuration)
	}
}

func TestQA_ConcurrentLedgerStorm_100Workers(t *testing.T) {
	ledger := NewLedger()

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
				_, err := ledger.AppendBlock(fmt.Sprintf("node-%d", workerID), "worker", []string{"EVENT"})
				if err != nil {
					errCh <- fmt.Errorf("worker %d iter %d error: %w", workerID, j, err)
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

	if err := ledger.ValidateChain(); err != nil {
		t.Fatalf("chain validation failed after concurrent storm: %v", err)
	}

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 54 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d blocks in %v (%.2f blocks/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkLedger_ValidateChain(b *testing.B) {
	ledger := NewLedger()
	for i := 0; i < 1000; i++ {
		_, _ = ledger.AppendBlock("c", "s", []string{"ev1", "ev2"})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ledger.ValidateChain()
	}
}
