package identity

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeIdentityScale_50KTokens(t *testing.T) {
	attestor := NewAttestor("enterprise.airom.internal", "scale-key")

	agentID := AgentIdentity{
		SPIFFEID: "spiffe://enterprise.airom.internal/ns/prod/agent/worker-1",
	}

	const numTokens = 50000
	start := time.Now()

	for i := 0; i < numTokens; i++ {
		cred := attestor.IssueSVID(agentID, 1*time.Hour)
		verified, err := attestor.VerifySVID(cred.Token)
		if err != nil || verified != agentID.SPIFFEID {
			t.Fatalf("failed at iter %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	opsPerSec := float64(numTokens*2) / duration.Seconds() // 50K issues + 50K verifications = 100K ops
	t.Logf("=== SPRINT 53 SCALE: 50K SPIFFE SVID ISSUE & VERIFICATION ROUND-TRIPS ===")
	t.Logf("Operations: %d (50K issues + 50K verifications)", numTokens*2)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f crypto ops/sec", opsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentIdentityStorm_100Workers(t *testing.T) {
	attestor := NewAttestor("enterprise.airom.internal", "conc-key")

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			agentID := AgentIdentity{
				SPIFFEID: fmt.Sprintf("spiffe://enterprise.airom.internal/ns/prod/agent/worker-%d", workerID),
			}
			for j := 0; j < iterations; j++ {
				cred := attestor.IssueSVID(agentID, 1*time.Hour)
				_, err := attestor.VerifySVID(cred.Token)
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

	totalOps := numWorkers * iterations * 2
	duration := time.Since(start)
	t.Logf("=== SPRINT 53 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkIdentity_VerifySVID(b *testing.B) {
	attestor := NewAttestor("enterprise.airom.internal", "bench-key")
	agentID := AgentIdentity{SPIFFEID: "spiffe://enterprise.airom.internal/ns/prod/agent/b"}
	cred := attestor.IssueSVID(agentID, 1*time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = attestor.VerifySVID(cred.Token)
	}
}
