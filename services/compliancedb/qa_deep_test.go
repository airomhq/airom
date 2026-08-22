package compliancedb

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// TestQA_DeepChainFuzzing stresses the hash-chain validator across 1,000 snapshots with pseudo-random tampering.
func TestQA_DeepChainFuzzing(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	chainLength := 1000
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repoID := "repo-deep-scale"

	chain := make([]ScanSnapshot, chainLength)
	prevHash := ""

	for i := 0; i < chainLength; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Minute)
		chain[i] = NewSnapshot(
			fmt.Sprintf("snap-%04d", i),
			repoID,
			fmt.Sprintf("commit-%04d", i),
			"main",
			ts,
			fmt.Sprintf("sha256-%04d", i),
			rng.Intn(500),
			rng.Intn(10),
			rng.Intn(20),
			rng.Intn(5),
			rng.Intn(3),
			prevHash,
			json.RawMessage(`{"status":"ok"}`),
		)
		prevHash = chain[i].SelfHash
	}

	// 1. Initial baseline verification on pristine 1,000-node chain
	report := ValidateChain(chain)
	if !report.Valid || report.TotalSnapshots != chainLength || report.BrokenAtIndex != -1 {
		t.Fatalf("expected pristine 1000-snapshot chain to be valid, got: %+v", report)
	}

	// 2. Perform 50 perturbation experiments across random indices
	for exp := 0; exp < 50; exp++ {
		tamperIdx := rng.Intn(chainLength)
		tamperType := rng.Intn(4)

		tamperedChain := make([]ScanSnapshot, chainLength)
		copy(tamperedChain, chain)

		switch tamperType {
		case 0: // Tamper controls_met
			tamperedChain[tamperIdx].ControlsMet += 1
		case 1: // Tamper AIBOM sha
			tamperedChain[tamperIdx].AIBOMSHA256 = fmt.Sprintf("tampered-sha-%d", exp)
		case 2: // Tamper controls_gap
			tamperedChain[tamperIdx].ControlsGap += 1
		case 3: // Tamper commit SHA
			tamperedChain[tamperIdx].CommitSHA = fmt.Sprintf("forged-commit-%d", exp)
		}

		res := ValidateChain(tamperedChain)
		if res.Valid {
			t.Fatalf("exp %d: expected tampering at index %d (type %d) to invalidate chain", exp, tamperIdx, tamperType)
		}
		if res.BrokenAtIndex != tamperIdx {
			t.Errorf("exp %d: expected broken index %d, got %d", exp, tamperIdx, res.BrokenAtIndex)
		}
	}
}

// TestQA_ConcurrentMultiTenantChains verifies thread safety and isolation across concurrent repository snapshot streams.
func TestQA_ConcurrentMultiTenantChains(t *testing.T) {
	numTenants := 20
	snapshotsPerTenant := 100
	baseTime := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	var wg sync.WaitGroup
	errCh := make(chan error, numTenants)

	for tenantID := 0; tenantID < numTenants; tenantID++ {
		wg.Add(1)
		go func(tID int) {
			defer wg.Done()
			repoID := fmt.Sprintf("tenant-%02d-repo", tID)
			chain := make([]ScanSnapshot, snapshotsPerTenant)
			prevHash := ""

			for s := 0; s < snapshotsPerTenant; s++ {
				ts := baseTime.Add(time.Duration(s*10) * time.Minute)
				chain[s] = NewSnapshot(
					fmt.Sprintf("snap-%d-%d", tID, s),
					repoID,
					fmt.Sprintf("commit-%d-%d", tID, s),
					"main",
					ts,
					fmt.Sprintf("aibom-%d-%d", tID, s),
					50+s,
					0,
					10,
					0,
					1,
					prevHash,
					nil,
				)
				prevHash = chain[s].SelfHash
			}

			// Validate generated chain
			report := ValidateChain(chain)
			if !report.Valid {
				errCh <- fmt.Errorf("tenant %d chain invalid at index %d: %s", tID, report.BrokenAtIndex, report.Reason)
				return
			}
		}(tenantID)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

// TestQA_ComplexMultiRegulationLifecycle simulates an enterprise 30-day timeline
// with 8 distinct regulatory controls undergoing multiple gap-and-remediation cycles.
func TestQA_ComplexMultiRegulationLifecycle(t *testing.T) {
	repoID := "repo-enterprise-corp"
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)

	controls := []struct {
		ID  string
		Ref string
	}{
		{"co.ai-act.impact-assessment", "CO SB 24-205 §6-1-1703"},
		{"co.ai-act.consumer-notice", "CO SB 24-205 §6-1-1704"},
		{"nyc.ll144.bias-audit", "NYC LL144 §20-871"},
		{"nyc.ll144.candidate-notice", "NYC LL144 §20-872"},
		{"ca.ab2013.training-data", "CA AB 2013 §3100"},
		{"ca.ab2013.pii-disclosure", "CA AB 2013 §3101"},
		{"fcra.risk.model-eval", "15 U.S.C. § 1681"},
		{"hipaa.phi.safeguards", "45 CFR § 164.312"},
	}

	var openIncidents []ComplianceIncident
	var allResolvedIncidents []ComplianceIncident
	prevHash := ""

	// Timeline Simulation over 10 check-in snapshots
	type TimelineStep struct {
		DayOffset    int
		GappedIDs    []string
		MetIDs       []string
		ExpectedOpen int
	}

	steps := []TimelineStep{
		// Day 0: Baseline - 3 controls in gap
		{0, []string{"co.ai-act.impact-assessment", "nyc.ll144.bias-audit", "ca.ab2013.training-data"}, []string{"co.ai-act.consumer-notice", "nyc.ll144.candidate-notice", "ca.ab2013.pii-disclosure", "fcra.risk.model-eval", "hipaa.phi.safeguards"}, 3},
		// Day 3: Repeat scan - same gaps, no new incidents opened
		{3, []string{"co.ai-act.impact-assessment", "nyc.ll144.bias-audit", "ca.ab2013.training-data"}, []string{"co.ai-act.consumer-notice", "nyc.ll144.candidate-notice", "ca.ab2013.pii-disclosure", "fcra.risk.model-eval", "hipaa.phi.safeguards"}, 3},
		// Day 7: Remediate NYC bias audit, but HIPAA PHI triggers a new gap
		{7, []string{"co.ai-act.impact-assessment", "ca.ab2013.training-data", "hipaa.phi.safeguards"}, []string{"nyc.ll144.bias-audit", "co.ai-act.consumer-notice", "nyc.ll144.candidate-notice", "ca.ab2013.pii-disclosure", "fcra.risk.model-eval"}, 3},
		// Day 14: Remediate CO impact assessment and CA training data
		{14, []string{"hipaa.phi.safeguards"}, []string{"co.ai-act.impact-assessment", "ca.ab2013.training-data", "nyc.ll144.bias-audit", "co.ai-act.consumer-notice", "nyc.ll144.candidate-notice", "ca.ab2013.pii-disclosure", "fcra.risk.model-eval"}, 1},
		// Day 21: Remediate HIPAA PHI - zero gaps!
		{21, []string{}, []string{"hipaa.phi.safeguards", "co.ai-act.impact-assessment", "ca.ab2013.training-data", "nyc.ll144.bias-audit", "co.ai-act.consumer-notice", "nyc.ll144.candidate-notice", "ca.ab2013.pii-disclosure", "fcra.risk.model-eval"}, 0},
	}

	for i, step := range steps {
		scanTime := t0.Add(time.Duration(step.DayOffset*24) * time.Hour)

		var evals []ControlEvaluation
		gapMap := make(map[string]bool)
		for _, gid := range step.GappedIDs {
			gapMap[gid] = true
		}

		for _, c := range controls {
			verdict := VerdictMet
			msg := ""
			if gapMap[c.ID] {
				verdict = VerdictGap
				msg = fmt.Sprintf("Gap detected for %s", c.ID)
			}
			evals = append(evals, ControlEvaluation{
				ID:         fmt.Sprintf("eval-%d-%s", i, c.ID),
				ControlID:  c.ID,
				StatuteRef: c.Ref,
				Verdict:    verdict,
				GapMessage: msg,
			})
		}

		snap := NewSnapshot(
			fmt.Sprintf("snap-step-%d", i),
			repoID,
			fmt.Sprintf("commit-%d", i),
			"main",
			scanTime,
			fmt.Sprintf("aibom-sha-%d", i),
			25,
			0,
			len(step.MetIDs),
			len(step.GappedIDs),
			0,
			prevHash,
			nil,
		)
		prevHash = snap.SelfHash

		newIncs, resolvedIncs, remOpen := ProcessSnapshotIncidents(openIncidents, snap, evals)
		openIncidents = remOpen
		allResolvedIncidents = append(allResolvedIncidents, resolvedIncs...)

		if len(openIncidents) != step.ExpectedOpen {
			t.Fatalf("step %d (Day %d): expected %d open incidents, got %d (new: %d, resolved: %d)", i, step.DayOffset, step.ExpectedOpen, len(openIncidents), len(newIncs), len(resolvedIncs))
		}
	}

	// Verify total resolved incidents count (3 initial + 1 HIPAA = 4 resolved)
	if len(allResolvedIncidents) != 4 {
		t.Fatalf("expected 4 total resolved incidents across lifecycle, got %d", len(allResolvedIncidents))
	}

	// Verify exact resolution duration calculations
	for _, res := range allResolvedIncidents {
		if res.ResolutionDurationHours == nil {
			t.Fatalf("incident %s missing resolution duration", res.ControlID)
		}
		hours := *res.ResolutionDurationHours
		switch res.ControlID {
		case "nyc.ll144.bias-audit":
			if hours != 7*24.0 { // Day 0 to Day 7 = 168h
				t.Errorf("nyc.ll144.bias-audit expected 168.0h, got %f", hours)
			}
		case "co.ai-act.impact-assessment":
			if hours != 14*24.0 { // Day 0 to Day 14 = 336h
				t.Errorf("co.ai-act.impact-assessment expected 336.0h, got %f", hours)
			}
		case "ca.ab2013.training-data":
			if hours != 14*24.0 { // Day 0 to Day 14 = 336h
				t.Errorf("ca.ab2013.training-data expected 336.0h, got %f", hours)
			}
		case "hipaa.phi.safeguards":
			if hours != (21-7)*24.0 { // Day 7 to Day 21 = 336h
				t.Errorf("hipaa.phi.safeguards expected 336.0h, got %f", hours)
			}
		}
	}
}

// TestQA_TimezoneNormalization ensures non-UTC timestamps produce identical hashes when representing identical UTC instants.
func TestQA_TimezoneNormalization(t *testing.T) {
	utcTime := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	estLocation := time.FixedZone("EST", -5*3600)
	estTime := utcTime.In(estLocation)

	hUTC := ComputeSnapshotHash("repo1", "c1", utcTime, "sha1", 5, 0, 1, "prev")
	hEST := ComputeSnapshotHash("repo1", "c1", estTime, "sha1", 5, 0, 1, "prev")

	if hUTC != hEST {
		t.Fatalf("expected timezone-invariant hash generation, got %s != %s", hUTC, hEST)
	}
}
