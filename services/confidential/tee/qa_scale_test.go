package tee

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeTEEScale_50KQuotes(t *testing.T) {
	verifier := NewVerifier(10)

	const numQuotes = 50000
	quotes := make([]AttestationQuote, numQuotes)
	now := time.Now().UTC()
	for i := 0; i < numQuotes; i++ {
		quotes[i] = AttestationQuote{
			Platform:          PlatformNVIDIACC,
			EnclaveID:         fmt.Sprintf("enclave_%d", i),
			MeasurementHash:   "sha384:valid_measurement_hash",
			PlatformCertChain: "VALID_NVIDIA_H100_RIM",
			TCBVersion:        15,
			SignedAt:          now,
		}
	}

	start := time.Now()
	for i := 0; i < numQuotes; i++ {
		verdict := verifier.VerifyQuote(quotes[i])
		if !verdict.Valid {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	quotesPerSec := float64(numQuotes) / duration.Seconds()
	t.Logf("=== SPRINT 96 SCALE: 50K HARDWARE TEE ATTESTATION QUOTES VERIFIED ===")
	t.Logf("Quotes:     %d", numQuotes)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f quotes/sec", quotesPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentTEEStorm_100Workers(t *testing.T) {
	verifier := NewVerifier(10)
	now := time.Now().UTC()
	quote := AttestationQuote{
		Platform:          PlatformAMDSEVSNP,
		EnclaveID:         "conc_enclave",
		MeasurementHash:   "sha384:valid",
		PlatformCertChain: "VALID_CERT",
		TCBVersion:        20,
		SignedAt:          now,
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
				verdict := verifier.VerifyQuote(quote)
				if !verdict.Valid {
					errCh <- fmt.Errorf("unexpected failure")
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
	t.Logf("=== SPRINT 96 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkTEE_VerifyQuote(b *testing.B) {
	verifier := NewVerifier(10)
	quote := AttestationQuote{
		Platform:          PlatformIntelTDX,
		EnclaveID:         "bench_enclave",
		MeasurementHash:   "sha384:valid",
		PlatformCertChain: "VALID_CERT",
		TCBVersion:        20,
		SignedAt:          time.Now().UTC(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.VerifyQuote(quote)
	}
}
