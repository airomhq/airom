package transfers

import (
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeTransferScale_50KDecisions(t *testing.T) {
	gate := NewGate()

	const numTransfers = 50000
	req := TransferRequest{
		TransferID:       "scale",
		Origin:           JurisdictionEU_EEA,
		Destination:      JurisdictionUS,
		ContainsPII:      true,
		MechanismClaimed: MechanismEU_US_DPF,
	}

	start := time.Now()
	for i := 0; i < numTransfers; i++ {
		dec := gate.EvaluateTransfer(req)
		if !dec.Approved {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	transfersPerSec := float64(numTransfers) / duration.Seconds()
	t.Logf("=== SPRINT 67 SCALE: 50K CROSS-BORDER AI TRANSFER DECISIONS ===")
	t.Logf("Transfers:   %d", numTransfers)
	t.Logf("Latency:     %v", duration)
	t.Logf("Throughput:  %.2f transfers/sec", transfersPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentTransferStorm_100Workers(t *testing.T) {
	gate := NewGate()
	req := TransferRequest{
		TransferID:       "conc",
		Origin:           JurisdictionEU_EEA,
		Destination:      JurisdictionJapan,
		MechanismClaimed: MechanismAdequacyDecision,
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
				dec := gate.EvaluateTransfer(req)
				if !dec.Approved {
					t.Errorf("unexpected rejection")
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
	t.Logf("=== SPRINT 67 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:   %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkTransfer_EvaluateTransfer(b *testing.B) {
	gate := NewGate()
	req := TransferRequest{Origin: JurisdictionEU_EEA, Destination: JurisdictionUS, MechanismClaimed: MechanismEU_US_DPF}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gate.EvaluateTransfer(req)
	}
}
