package signature

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeSignatureScale_10KVerifications(t *testing.T) {
	keyPair, _ := GenerateKeyPair()
	payload := []byte("high_speed_rule_layer_content")
	env, _ := SignRuleBundle(payload, keyPair, "compliance@corp.com", "issuer", 1*time.Hour)

	verifier := NewVerifier(VerificationPolicy{})

	const numOps = 10000
	start := time.Now()

	for i := 0; i < numOps; i++ {
		if err := verifier.Verify(payload, env); err != nil {
			t.Fatalf("verify failed at %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numOps) / duration.Seconds()
	t.Logf("=== SPRINT 40 SCALE: 10K ED25519 SIGNATURE VERIFICATIONS ===")
	t.Logf("Verifications: %d", numOps)
	t.Logf("Latency:       %v", duration)
	t.Logf("Throughput:    %.2f verifications/sec", opsPerSec)

	if duration > 2*time.Second {
		t.Errorf("expected execution < 2s, took %v", duration)
	}
}

func TestQA_ConcurrentSignatureStorm_100Workers(t *testing.T) {
	keyPair, _ := GenerateKeyPair()
	payload := []byte("concurrent_payload")
	env, _ := SignRuleBundle(payload, keyPair, "signer@corp.com", "issuer", 1*time.Hour)

	verifier := NewVerifier(VerificationPolicy{})

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
				if err := verifier.Verify(payload, env); err != nil {
					errCh <- fmt.Errorf("worker %d iter %d verify failed: %w", workerID, j, err)
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
	t.Logf("=== SPRINT 40 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:     %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkSignature_Verify(b *testing.B) {
	keyPair, _ := GenerateKeyPair()
	payload := []byte("bench_payload")
	env, _ := SignRuleBundle(payload, keyPair, "signer@corp.com", "issuer", 1*time.Hour)
	verifier := NewVerifier(VerificationPolicy{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.Verify(payload, env)
	}
}
