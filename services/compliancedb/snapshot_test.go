package compliancedb

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestComputeSnapshotHash_Deterministic(t *testing.T) {
	repoID := "repo-123"
	commitSHA := "abcdef1234567890"
	ts := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	aibomSHA := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	met := 4
	gap := 1
	manual := 2
	prevHash := "0000000000000000000000000000000000000000000000000000000000000000"

	h1 := ComputeSnapshotHash(repoID, commitSHA, ts, aibomSHA, met, gap, manual, prevHash)
	h2 := ComputeSnapshotHash(repoID, commitSHA, ts, aibomSHA, met, gap, manual, prevHash)

	if h1 == "" || len(h1) != 64 {
		t.Fatalf("expected 64-char hex hash, got %q", h1)
	}
	if h1 != h2 {
		t.Fatalf("expected deterministic hash output, got %q != %q", h1, h2)
	}

	// Change any field and verify hash changes
	h3 := ComputeSnapshotHash(repoID, "different-commit", ts, aibomSHA, met, gap, manual, prevHash)
	if h1 == h3 {
		t.Fatalf("expected different hash on commit change")
	}

	h4 := ComputeSnapshotHash(repoID, commitSHA, ts, aibomSHA, met+1, gap, manual, prevHash)
	if h1 == h4 {
		t.Fatalf("expected different hash on controls change")
	}
}

func TestValidateChain_Valid(t *testing.T) {
	baseTime := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	repoID := "repo-xyz"

	var chain []ScanSnapshot
	prevHash := ""

	for i := 0; i < 5; i++ {
		snapTime := baseTime.Add(time.Duration(i) * time.Hour)
		snap := NewSnapshot(
			fmt.Sprintf("snap-%d", i),
			repoID,
			fmt.Sprintf("commit-%d", i),
			"main",
			snapTime,
			fmt.Sprintf("aibom-sha-%d", i),
			10+i,
			i,
			5,
			i%2,
			1,
			prevHash,
			json.RawMessage(`{"components": []}`),
		)
		chain = append(chain, snap)
		prevHash = snap.SelfHash
	}

	report := ValidateChain(chain)
	if !report.Valid {
		t.Fatalf("expected valid chain, got broken at index %d: %s", report.BrokenAtIndex, report.Reason)
	}
	if report.TotalSnapshots != 5 {
		t.Errorf("expected 5 snapshots, got %d", report.TotalSnapshots)
	}
	if report.BrokenAtIndex != -1 {
		t.Errorf("expected brokenAtIndex -1, got %d", report.BrokenAtIndex)
	}
}

func TestValidateChain_TamperedPayload(t *testing.T) {
	baseTime := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	repoID := "repo-xyz"

	var chain []ScanSnapshot
	prevHash := ""

	for i := 0; i < 4; i++ {
		snapTime := baseTime.Add(time.Duration(i) * time.Hour)
		snap := NewSnapshot(
			fmt.Sprintf("snap-%d", i),
			repoID,
			fmt.Sprintf("commit-%d", i),
			"main",
			snapTime,
			fmt.Sprintf("aibom-sha-%d", i),
			10+i,
			0,
			5,
			0,
			0,
			prevHash,
			nil,
		)
		chain = append(chain, snap)
		prevHash = snap.SelfHash
	}

	// Tamper: modify historical snapshot controls_met at index 1 without updating self_hash
	chain[1].ControlsMet = 99

	report := ValidateChain(chain)
	if report.Valid {
		t.Fatalf("expected invalid chain due to tampered snapshot payload")
	}
	if report.BrokenAtIndex != 1 {
		t.Errorf("expected brokenAtIndex 1, got %d", report.BrokenAtIndex)
	}
}

func TestValidateChain_TamperedChainContinuity(t *testing.T) {
	baseTime := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	repoID := "repo-xyz"

	var chain []ScanSnapshot
	prevHash := ""

	for i := 0; i < 4; i++ {
		snapTime := baseTime.Add(time.Duration(i) * time.Hour)
		snap := NewSnapshot(
			fmt.Sprintf("snap-%d", i),
			repoID,
			fmt.Sprintf("commit-%d", i),
			"main",
			snapTime,
			fmt.Sprintf("aibom-sha-%d", i),
			10,
			0,
			5,
			0,
			0,
			prevHash,
			nil,
		)
		chain = append(chain, snap)
		prevHash = snap.SelfHash
	}

	// Tamper: replace index 1 entirely with a different snapshot, recalculate its self_hash,
	// but index 2 will still point to the old parent hash
	tamperedSnap1 := NewSnapshot(
		"snap-1",
		repoID,
		"forged-commit-1",
		"main",
		baseTime.Add(1*time.Hour),
		"forged-aibom",
		10,
		0,
		5,
		0,
		0,
		chain[0].SelfHash,
		nil,
	)
	chain[1] = tamperedSnap1

	report := ValidateChain(chain)
	if report.Valid {
		t.Fatalf("expected chain validation to detect broken parent link")
	}
	if report.BrokenAtIndex != 2 {
		t.Errorf("expected broken link detected at child index 2, got %d", report.BrokenAtIndex)
	}
}

func TestValidateChain_NonMonotonicTimestamp(t *testing.T) {
	baseTime := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	repoID := "repo-xyz"

	snap0 := NewSnapshot("snap-0", repoID, "c0", "main", baseTime, "sha0", 10, 0, 5, 0, 0, "", nil)
	// snap1 timestamp earlier than snap0
	snap1Time := baseTime.Add(-1 * time.Hour)
	snap1 := NewSnapshot("snap-1", repoID, "c1", "main", snap1Time, "sha1", 10, 0, 5, 0, 0, snap0.SelfHash, nil)

	report := ValidateChain([]ScanSnapshot{snap0, snap1})
	if report.Valid {
		t.Fatalf("expected validation failure on non-monotonic timestamp")
	}
	if report.BrokenAtIndex != 1 {
		t.Errorf("expected brokenAtIndex 1, got %d", report.BrokenAtIndex)
	}
}

func TestProcessSnapshotIncidents_Lifecycle(t *testing.T) {
	repoID := "repo-lifecycle"
	t0 := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snap0 := NewSnapshot("snap-0", repoID, "c0", "main", t0, "sha0", 10, 0, 2, 1, 0, "", nil)

	evals0 := []ControlEvaluation{
		{ControlID: "co.ai-act.impact-assessment", StatuteRef: "CO SB 24-205", Verdict: VerdictGap, GapMessage: "Missing assessment"},
		{ControlID: "nyc.ll144.bias-audit", StatuteRef: "NYC LL144", Verdict: VerdictMet},
	}

	// 1. Initial scan: opens incident for CO impact assessment
	newInc, resolvedInc, remaining := ProcessSnapshotIncidents(nil, snap0, evals0)
	if len(newInc) != 1 {
		t.Fatalf("expected 1 new incident, got %d", len(newInc))
	}
	if len(resolvedInc) != 0 {
		t.Fatalf("expected 0 resolved incidents, got %d", len(resolvedInc))
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining open incident, got %d", len(remaining))
	}
	if newInc[0].ControlID != "co.ai-act.impact-assessment" || newInc[0].Status != IncidentStatusOpen {
		t.Errorf("unexpected incident data: %+v", newInc[0])
	}

	// 2. Second scan 48 hours later: still gap, should not create duplicate incident
	t1 := t0.Add(48 * time.Hour)
	snap1 := NewSnapshot("snap-1", repoID, "c1", "main", t1, "sha1", 10, 0, 2, 1, 0, snap0.SelfHash, nil)
	newInc1, resolvedInc1, remaining1 := ProcessSnapshotIncidents(remaining, snap1, evals0)
	if len(newInc1) != 0 {
		t.Errorf("expected 0 new incidents on repeated gap, got %d", len(newInc1))
	}
	if len(resolvedInc1) != 0 {
		t.Errorf("expected 0 resolved incidents, got %d", len(resolvedInc1))
	}
	if len(remaining1) != 1 {
		t.Errorf("expected 1 remaining open incident, got %d", len(remaining1))
	}

	// 3. Third scan 72 hours from start: control remediated (now MET)
	t2 := t0.Add(72 * time.Hour)
	snap2 := NewSnapshot("snap-2", repoID, "c2", "main", t2, "sha2", 10, 0, 3, 0, 0, snap1.SelfHash, nil)
	evals2 := []ControlEvaluation{
		{ControlID: "co.ai-act.impact-assessment", StatuteRef: "CO SB 24-205", Verdict: VerdictMet},
		{ControlID: "nyc.ll144.bias-audit", StatuteRef: "NYC LL144", Verdict: VerdictMet},
	}

	newInc2, resolvedInc2, remaining2 := ProcessSnapshotIncidents(remaining1, snap2, evals2)
	if len(newInc2) != 0 {
		t.Errorf("expected 0 new incidents, got %d", len(newInc2))
	}
	if len(resolvedInc2) != 1 {
		t.Fatalf("expected 1 resolved incident, got %d", len(resolvedInc2))
	}
	if len(remaining2) != 0 {
		t.Errorf("expected 0 remaining open incidents, got %d", len(remaining2))
	}

	resolved := resolvedInc2[0]
	if resolved.Status != IncidentStatusResolved {
		t.Errorf("expected status RESOLVED, got %s", resolved.Status)
	}
	if resolved.ResolvingSnapshotID == nil || *resolved.ResolvingSnapshotID != snap2.ID {
		t.Errorf("expected resolving snapshot snap-2, got %v", resolved.ResolvingSnapshotID)
	}
	if resolved.ResolutionDurationHours == nil || *resolved.ResolutionDurationHours != 72.0 {
		t.Errorf("expected 72.0 duration hours, got %v", resolved.ResolutionDurationHours)
	}
}

func BenchmarkComputeSnapshotHash(b *testing.B) {
	repoID := "repo-bench"
	commitSHA := "abcdef1234567890"
	ts := time.Now().UTC()
	aibomSHA := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	met := 10
	gap := 2
	manual := 3
	prevHash := "0000000000000000000000000000000000000000000000000000000000000000"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeSnapshotHash(repoID, commitSHA, ts, aibomSHA, met, gap, manual, prevHash)
	}
}

func BenchmarkValidateChain(b *testing.B) {
	baseTime := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	repoID := "repo-bench"

	var chain []ScanSnapshot
	prevHash := ""

	for i := 0; i < 100; i++ {
		snapTime := baseTime.Add(time.Duration(i) * time.Hour)
		snap := NewSnapshot(
			fmt.Sprintf("snap-%d", i),
			repoID,
			fmt.Sprintf("commit-%d", i),
			"main",
			snapTime,
			fmt.Sprintf("aibom-sha-%d", i),
			10,
			0,
			5,
			0,
			0,
			prevHash,
			nil,
		)
		chain = append(chain, snap)
		prevHash = snap.SelfHash
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateChain(chain)
	}
}
