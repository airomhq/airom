package pqc

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremePQCLedgerScale_50KBlocks(t *testing.T) {
	ledger := NewLedger()

	const numBlocks = 50000
	start := time.Now()

	for i := 0; i < numBlocks; i++ {
		_ = ledger.AppendBlock(fmt.Sprintf("repo_%d", i), fmt.Sprintf("snap_hash_%d", i))
	}
	appendDuration := time.Since(start)

	verifyStart := time.Now()
	proof := ledger.VerifyIntegrity()
	verifyDuration := time.Since(verifyStart)

	if !proof.IntegrityValid || proof.TotalBlocks != numBlocks+1 {
		t.Fatalf("failed scale ledger integrity check")
	}

	totalDuration := appendDuration + verifyDuration
	opsPerSec := float64(numBlocks) / totalDuration.Seconds()
	t.Logf("=== SPRINT 95 SCALE: 50K PQC SHA3-512 LEDGER BLOCKS APPENDED & VERIFIED ===")
	t.Logf("Blocks:     %d", numBlocks)
	t.Logf("Append Lat: %v", appendDuration)
	t.Logf("Verify Lat: %v", verifyDuration)
	t.Logf("Throughput: %.2f blocks/sec", opsPerSec)

	if totalDuration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", totalDuration)
	}
}

func TestQA_ConcurrentPQCLedgerStorm_100Workers(t *testing.T) {
	ledger := NewLedger()

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = ledger.AppendBlock(fmt.Sprintf("worker_%d", workerID), "hash")
			}
		}(i)
	}

	wg.Wait()

	proof := ledger.VerifyIntegrity()
	if !proof.IntegrityValid {
		t.Fatalf("concurrent ledger integrity failed")
	}

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 95 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkPQCLedger_AppendBlock(b *testing.B) {
	ledger := NewLedger()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ledger.AppendBlock("repo-bench", "snap-bench")
	}
}
