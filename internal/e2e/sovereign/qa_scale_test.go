package sovereign

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/services/sovereign/exportcontrol"
	"github.com/airomhq/airom/services/sovereign/matrix"
	"github.com/airomhq/airom/services/sovereign/transfers"
	"github.com/airomhq/airom/services/surveillance/drift"
	"github.com/airomhq/airom/services/surveillance/fairness"
	"github.com/airomhq/airom/services/swarm/circuit"
	"github.com/airomhq/airom/services/swarm/poa"
)

func TestQA_ExtremeSovereignE2EScale_5KLifecycles(t *testing.T) {
	poaGate := poa.NewGate()
	poaGate.RegisterGrant(poa.POAGrant{
		AgentID:              "scale-agent",
		AuthorizedScopes:     []poa.POAScope{poa.ScopeFinancialPayment},
		PerTransactionMaxUSD: 10000.0,
	})

	transferGate := transfers.NewGate()
	exportEngine := exportcontrol.NewEngine()
	harmonizer := matrix.NewHarmonizer()
	driftDetector := drift.NewDetector()
	fairnessEngine := fairness.NewTelemetryEngine()
	breaker := circuit.NewBreaker(circuit.SafetyCeilings{MaxHopDepth: 1000000, MaxTotalMessages: 1000000})

	inv := &airom.Inventory{Components: []airom.Component{{ID: "c1", Kind: airom.KindHostedLLM}}}
	bins := []float64{100, 200, 300, 200, 100}
	groups := []fairness.GroupStatistics{
		{GroupLabel: "A", TotalApplied: 100, TotalSelected: 50},
		{GroupLabel: "B", TotalApplied: 100, TotalSelected: 45},
	}

	const numLifecycles = 5000
	start := time.Now()

	for i := 0; i < numLifecycles; i++ {
		// 1. Swarm Circuit Check
		_ = breaker.AllowDelegation(circuit.DelegationCall{CurrentHop: 1, DriftScore: 0.10})

		// 2. POA Gate Check
		_ = poaGate.EvaluateAction(poa.ActionRequest{AgentID: "scale-agent", Scope: poa.ScopeFinancialPayment, AmountUSD: 10.0})

		// 3. Cross-Border Transfer Gate
		_ = transferGate.EvaluateTransfer(transfers.TransferRequest{Origin: transfers.JurisdictionEU_EEA, Destination: transfers.JurisdictionUS, MechanismClaimed: transfers.MechanismEU_US_DPF})

		// 4. Export Control Screen
		_ = exportEngine.ScreenModel(exportcontrol.ModelExportSpec{ModelName: "Model", TotalTrainingFLOPs: 1e24, DestinationCountry: "Japan"})

		// 5. Global Matrix Harmonize
		_ = harmonizer.Harmonize("Model", "logistics", inv)

		// 6. Drift Check
		_ = driftDetector.ComputePSI("f", bins, bins)

		// 7. Fairness Check
		_ = fairnessEngine.EvaluateFairness("Model", groups)
	}
	duration := time.Since(start)

	lifecyclesPerSec := float64(numLifecycles) / duration.Seconds()
	t.Logf("=== SPRINT 75 SCALE: 5K COMPLETE SOVEREIGN ENTERPRISE GOVERNANCE LIFECYCLES ===")
	t.Logf("Lifecycles: %d", numLifecycles)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f lifecycles/sec", lifecyclesPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentSovereignE2EStorm_100Workers(t *testing.T) {
	poaGate := poa.NewGate()
	for i := 0; i < 100; i++ {
		poaGate.RegisterGrant(poa.POAGrant{
			AgentID:              fmt.Sprintf("agent-%d", i),
			AuthorizedScopes:     []poa.POAScope{poa.ScopeFinancialPayment},
			PerTransactionMaxUSD: 1000.0,
		})
	}

	transferGate := transfers.NewGate()
	exportEngine := exportcontrol.NewEngine()
	harmonizer := matrix.NewHarmonizer()

	const numWorkers = 100
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				dec := poaGate.EvaluateAction(poa.ActionRequest{
					AgentID:   fmt.Sprintf("agent-%d", workerID),
					Scope:     poa.ScopeFinancialPayment,
					AmountUSD: 5.0,
				})
				if !dec.Approved {
					errCh <- fmt.Errorf("worker %d iter %d rejected", workerID, j)
					return
				}
				_ = transferGate.EvaluateTransfer(transfers.TransferRequest{Origin: transfers.JurisdictionEU_EEA, Destination: transfers.JurisdictionJapan, MechanismClaimed: transfers.MechanismAdequacyDecision})
				_ = exportEngine.ScreenModel(exportcontrol.ModelExportSpec{ModelName: "Model", DestinationCountry: "Japan"})
				_ = harmonizer.Harmonize("Model", "logistics", nil)
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
	t.Logf("=== SPRINT 75 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d full lifecycles in %v (%.2f lifecycles/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkSovereign_FullGovernancePipeline(b *testing.B) {
	poaGate := poa.NewGate()
	poaGate.RegisterGrant(poa.POAGrant{AgentID: "bench", AuthorizedScopes: []poa.POAScope{poa.ScopeFinancialPayment}, PerTransactionMaxUSD: 10000.0})
	transferGate := transfers.NewGate()
	exportEngine := exportcontrol.NewEngine()
	harmonizer := matrix.NewHarmonizer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = poaGate.EvaluateAction(poa.ActionRequest{AgentID: "bench", Scope: poa.ScopeFinancialPayment, AmountUSD: 10.0})
		_ = transferGate.EvaluateTransfer(transfers.TransferRequest{Origin: transfers.JurisdictionEU_EEA, Destination: transfers.JurisdictionUS, MechanismClaimed: transfers.MechanismEU_US_DPF})
		_ = exportEngine.ScreenModel(exportcontrol.ModelExportSpec{ModelName: "Model", DestinationCountry: "UK"})
		_ = harmonizer.Harmonize("Model", "logistics", nil)
	}
}
