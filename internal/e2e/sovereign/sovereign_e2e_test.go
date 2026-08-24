// Package sovereign implements master end-to-end integration and conformance tests
// across the Sovereign Enterprise AI Governance platform (ARCHITECTURE.md §16).
package sovereign

import (
	"math/rand"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/tui/sovereign"
	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/services/airgap/bundle"
	"github.com/airomhq/airom/services/forensics/memorization"
	"github.com/airomhq/airom/services/forensics/stego"
	"github.com/airomhq/airom/services/forensics/tensors"
	"github.com/airomhq/airom/services/sovereign/exportcontrol"
	"github.com/airomhq/airom/services/sovereign/matrix"
	"github.com/airomhq/airom/services/sovereign/transfers"
	"github.com/airomhq/airom/services/surveillance/drift"
	"github.com/airomhq/airom/services/surveillance/fairness"
	"github.com/airomhq/airom/services/surveillance/incidents"
	"github.com/airomhq/airom/services/swarm/circuit"
	"github.com/airomhq/airom/services/swarm/inspector"
	"github.com/airomhq/airom/services/swarm/poa"
)

func TestSovereign_MasterEndToEndEcosystemFlow(t *testing.T) {
	// 1. Neural Forensics: Tensor Backdoor Scan
	tensorDetector := tensors.NewDetector()
	r := rand.New(rand.NewSource(42))
	weights := make([]float32, 1000)
	for i := 0; i < len(weights); i++ {
		weights[i] = float32(r.NormFloat64() * 0.02)
	}
	header := tensors.TensorLayerHeader{Name: "model.layers.0.weight", Format: tensors.FormatSafetensors, NumWeights: 1000}
	tensorResult := tensorDetector.ScanCheckpoint("Sovereign-Llama-70B", tensors.FormatSafetensors, []tensors.LayerData{{Header: header, Weights: weights}})
	if tensorResult.IsPoisoned || tensorResult.IntegrityScore != 100.0 {
		t.Fatalf("expected clean tensor scan: %+v", tensorResult)
	}

	// 2. Neural Forensics: Steganography Scan
	stegoExtractor := stego.NewExtractor()
	carrier := make([]byte, 256)
	for i := range carrier {
		carrier[i] = byte((i * 2) % 256)
	}
	_, stegoDetected := stegoExtractor.ExtractLSBBytes("model.layers.0.weight", carrier)
	if stegoDetected {
		t.Fatalf("expected no stego in clean carrier")
	}

	// 3. Neural Forensics: Training Data Extraction / GDPR Memorization
	memAuditor := memorization.NewAuditor()
	probe := memorization.CanaryProbe{ID: "p1", ExpectedTail: "confidential token"}
	scorecard := memAuditor.AuditModel("Sovereign-Llama-70B", []memorization.CanaryProbe{probe}, map[string]string{"p1": "safe generic reply"})
	if !scorecard.GDPRCompliant || scorecard.ExtractedCount != 0 {
		t.Fatalf("expected GDPR compliance on unmemorized output")
	}

	// 4. Multi-Agent Swarm Governance: Topology Inspector
	swarmIns := inspector.NewInspector("Sovereign financial transaction audit")
	swarmIns.RegisterAgent(inspector.SwarmAgent{ID: "agent-1", Name: "Supervisor", Framework: inspector.ProtocolLangGraph})
	swarmIns.RegisterAgent(inspector.SwarmAgent{ID: "agent-2", Name: "Worker", Framework: inspector.ProtocolLangGraph, ParentAgent: "agent-1"})
	swarmIns.RecordMessage(inspector.SwarmMessage{
		MessageID:  "m1",
		SenderID:   "agent-1",
		ReceiverID: "agent-2",
		Intent:     "Audit statutory records for financial transaction",
		Payload:    "Executing query",
	})
	topo := swarmIns.GetTopology()
	if len(topo.Agents) != 2 || len(topo.Messages) != 1 {
		t.Fatalf("expected 2 agents and 1 message in topology")
	}

	// 5. Multi-Agent Swarm Governance: Delegation Circuit Breaker
	breaker := circuit.NewBreaker(circuit.DefaultSafetyCeilings())
	err := breaker.AllowDelegation(circuit.DelegationCall{CurrentHop: 1, DriftScore: 0.10, CostDelta: 0.25})
	if err != nil {
		t.Fatalf("expected allowed delegation, got %v", err)
	}

	// 6. Multi-Agent Swarm Governance: Agentic POA Bounds Gate
	poaGate := poa.NewGate()
	poaGate.RegisterGrant(poa.POAGrant{
		AgentID:              "agent-1",
		AuthorizedScopes:     []poa.POAScope{poa.ScopeFinancialPayment},
		PerTransactionMaxUSD: 5000.0,
		DualCustodyThreshold: 1000.0,
	})
	poaDec := poaGate.EvaluateAction(poa.ActionRequest{
		RequestID: "poa-001",
		AgentID:   "agent-1",
		Scope:     poa.ScopeFinancialPayment,
		AmountUSD: 250.0,
	})
	if !poaDec.Approved {
		t.Fatalf("expected approved POA action: %+v", poaDec)
	}

	// 7. Global Sovereign AI: Cross-Border Transfer Gate
	transferGate := transfers.NewGate()
	transferDec := transferGate.EvaluateTransfer(transfers.TransferRequest{
		TransferID:       "x-transfer-01",
		Origin:           transfers.JurisdictionEU_EEA,
		Destination:      transfers.JurisdictionUS,
		MechanismClaimed: transfers.MechanismEU_US_DPF,
	})
	if !transferDec.Approved {
		t.Fatalf("expected approved transfer under DPF: %+v", transferDec)
	}

	// 8. Global Sovereign AI: Export Control & Compute Thresholds
	exportEngine := exportcontrol.NewEngine()
	exportRes := exportEngine.ScreenModel(exportcontrol.ModelExportSpec{
		ModelName:          "Sovereign-Llama-70B",
		TotalTrainingFLOPs: 5e24,
		RecipientEntity:    "Enterprise-Consumer",
		DestinationCountry: "Germany",
	})
	if exportRes.Requirement != exportcontrol.NoLicenseRequired_NLR {
		t.Fatalf("expected NLR for standard export: %+v", exportRes)
	}

	// 9. Global Sovereign AI: Unified Regulatory Matrix
	harmonizer := matrix.NewHarmonizer()
	inv := &airom.Inventory{Components: []airom.Component{{ID: "c1", Kind: airom.KindHostedLLM, Name: "llama-3-70b"}}}
	matrixRes := harmonizer.Harmonize("Sovereign-Llama-70B", "supply_chain_logistics", inv)
	if matrixRes.OverallVerdict != "GLOBAL_PASS" || matrixRes.TotalFrameworks != 6 {
		t.Fatalf("expected GLOBAL_PASS across all 6 frameworks: %+v", matrixRes)
	}

	// 10. Continuous Post-Market Surveillance: Concept Drift PSI
	driftDetector := drift.NewDetector()
	bins := []float64{100, 200, 300, 200, 100}
	driftRes := driftDetector.ComputePSI("embedding_feature", bins, bins)
	if driftRes.Severity != drift.DriftNegligible {
		t.Fatalf("expected negligible drift")
	}

	// 11. Continuous Post-Market Surveillance: Serious Incident 72h Triage
	triageEngine := incidents.NewTriageEngine()
	pkg := triageEngine.TriageIncident(incidents.AIIncidentInput{
		IncidentID: "inc-e2e",
		Severity:   incidents.SeverityDeathOrPhysicalHarm,
		OccurredAt: time.Now().UTC(),
	})
	if pkg.NotificationWindow != "72_HOURS" || len(pkg.TargetAuthorities) < 3 {
		t.Fatalf("expected 72_HOURS window with 3 authorities: %+v", pkg)
	}

	// 12. Continuous Post-Market Surveillance: Demographic Parity 4/5ths
	fairnessEngine := fairness.NewTelemetryEngine()
	fairnessScore := fairnessEngine.EvaluateFairness("Sovereign-Llama-70B", []fairness.GroupStatistics{
		{GroupLabel: "Cohort_1", TotalApplied: 1000, TotalSelected: 500},
		{GroupLabel: "Cohort_2", TotalApplied: 1000, TotalSelected: 450},
	})
	if fairnessScore.OverallFairness != "FAIR_COMPLIANT" {
		t.Fatalf("expected fair compliant scorecard")
	}

	// 13. Offline Air-Gap Bundle Compiler
	compiler := bundle.NewCompiler([]byte("master-e2e-secret-key"))
	agPkg := compiler.BuildBundle("ag-e2e", "v1.0.0", map[string][]byte{"rules/sovereign.yaml": []byte("sovereign: true")}, 1, 1, 1)
	if err := compiler.VerifyBundle(agPkg); err != nil {
		t.Fatalf("expected valid airgap bundle verification: %v", err)
	}

	// 14. Sovereign Desktop Terminal UI Frame Rendering
	renderer := sovereign.NewRenderer()
	frame := renderer.RenderFrame(sovereign.TerminalState{
		ActiveView:      sovereign.ViewDashboard,
		SystemName:      "Sovereign-Llama-70B",
		ComplianceScore: 100.0,
		RenderedAt:      time.Now().UTC(),
	}, 80, 24)
	if len(frame) < 100 {
		t.Fatalf("expected fully rendered terminal frame")
	}
}
