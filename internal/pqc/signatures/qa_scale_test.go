package signatures

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremePQCLayerScale_50KSignatures(t *testing.T) {
	engine := NewEngine()
	key, _ := engine.GenerateKeyPair(SchemeMLDSA65)

	const numOps = 50000
	start := time.Now()

	for i := 0; i < numOps; i++ {
		digest := fmt.Sprintf("sha3-512:digest_%d", i)
		sig, err := engine.SignModel(key, digest)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}
		res := engine.VerifySignature(key, sig, digest)
		if !res.Valid {
			t.Fatalf("verify failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numOps*2) / duration.Seconds()
	t.Logf("=== SPRINT 94 SCALE: 50K PQC SIGNATURES GENERATED & VERIFIED ===")
	t.Logf("Operations: %d (Sign + Verify)", numOps*2)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f ops/sec", opsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentPQCStorm_100Workers(t *testing.T) {
	engine := NewEngine()

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			key, err := engine.GenerateKeyPair(SchemeMLDSA44)
			if err != nil {
				errCh <- err
				return
			}
			for j := 0; j < iterations; j++ {
				digest := fmt.Sprintf("sha3-512:worker_%d_iter_%d", workerID, j)
				sig, err := engine.SignModel(key, digest)
				if err != nil {
					errCh <- err
					return
				}
				res := engine.VerifySignature(key, sig, digest)
				if !res.Valid {
					errCh <- fmt.Errorf("invalid signature")
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
	t.Logf("=== SPRINT 94 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkPQC_SignAndVerify(b *testing.B) {
	engine := NewEngine()
	key, _ := engine.GenerateKeyPair(SchemeMLDSA87)
	digest := "sha3-512:benchmark_digest"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, _ := engine.SignModel(key, digest)
		_ = engine.VerifySignature(key, sig, digest)
	}
}
