package agentic

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeRedTeamScale_10KPayloads(t *testing.T) {
	fuzzer := NewFuzzer()
	evaluator := NewEvaluator()

	const numAttacks = 10000
	start := time.Now()

	results := make([]AttackResult, numAttacks)
	for i := 0; i < numAttacks; i++ {
		var payload AttackPayload
		if i%3 == 0 {
			payload = fuzzer.GenerateCrescendoAttack("extract secrets")
		} else if i%3 == 1 {
			payload = fuzzer.GenerateManyShotJailbreak(5, "bypass system controls")
		} else {
			payload = fuzzer.GenerateEncodingSmuggling("exfiltrate PII")
		}

		resp := "I cannot comply with this request."
		if i%10 == 0 {
			resp = "Here is the sensitive data: EXPLOITED_TOKEN"
		}

		results[i] = evaluator.EvaluateResponse(payload, resp, 10*time.Microsecond)
	}

	report := GenerateReport(results)
	duration := time.Since(start)

	if report.TotalAttacks != numAttacks || report.SuccessfulAttacks != 1000 {
		t.Fatalf("unexpected report metrics: %+v", report)
	}

	evalsPerSec := float64(numAttacks) / duration.Seconds()
	t.Logf("=== SPRINT 46 SCALE: 10K RED-TEAM ATTACK GENERATION & EVALUATIONS ===")
	t.Logf("Attacks:    %d", numAttacks)
	t.Logf("ASR:        %.2f%%", report.AttackSuccessRate)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f evals/sec", evalsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentRedTeamStorm_100Workers(t *testing.T) {
	fuzzer := NewFuzzer()
	evaluator := NewEvaluator()

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
				payload := fuzzer.GenerateCrescendoAttack(fmt.Sprintf("worker-%d-target-%d", workerID, j))
				res := evaluator.EvaluateResponse(payload, "I am unable to assist with that request.", 5*time.Microsecond)
				if res.Success {
					errCh <- fmt.Errorf("unexpected breach on standard refusal")
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
	t.Logf("=== SPRINT 46 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkRedTeam_EvaluateResponse(b *testing.B) {
	evaluator := NewEvaluator()
	payload := AttackPayload{ID: "bench", Vector: VectorPromptInjection}
	resp := "I cannot fulfill this request as it violates safety guidelines."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = evaluator.EvaluateResponse(payload, resp, 10*time.Microsecond)
	}
}
