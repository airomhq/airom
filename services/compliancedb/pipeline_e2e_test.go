package compliancedb

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/services/anomaly"
)

// TestQA_CrossServicePipeline simulates an end-to-end multi-sprint workflow:
// Scan Diff -> AnomalyEngine Evaluation -> ComplianceDB Ingestion & Hash-Chaining -> Incident Management.
func TestQA_CrossServicePipeline(t *testing.T) {
	repoID := "repo-cross-pipeline"
	t0 := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)

	// Step 1: Scan 1 (Base) - Clean initial state
	baseDiff := anomaly.DiffReport{
		BaseCommit: "commit-0",
		HeadCommit: "commit-1",
	}
	baseReport := anomaly.EvaluateAnomalies(baseDiff, nil)
	if !baseReport.Clean {
		t.Fatalf("expected clean initial scan")
	}

	snap0 := NewSnapshot(
		"snap-0",
		repoID,
		"commit-1",
		"main",
		t0,
		"aibom-sha-commit1",
		12,
		0,
		4,
		0,
		0,
		"",
		json.RawMessage(`{"components": [{"name": "approved-core"}]}`),
	)

	evals0 := []ControlEvaluation{
		{ID: "ev-0-1", SnapshotID: snap0.ID, ControlID: "co.ai-act.impact-assessment", StatuteRef: "CO SB 24-205", Verdict: VerdictMet},
		{ID: "ev-0-2", SnapshotID: snap0.ID, ControlID: "nyc.ll144.bias-audit", StatuteRef: "NYC LL144", Verdict: VerdictMet},
	}

	newIncs0, resolvedIncs0, activeIncs0 := ProcessSnapshotIncidents(nil, snap0, evals0)
	if len(newIncs0) != 0 || len(resolvedIncs0) != 0 || len(activeIncs0) != 0 {
		t.Fatalf("expected zero incidents on clean baseline, got %d active", len(activeIncs0))
	}

	// Step 2: Scan 2 (PR introduces Shadow AI and Hiring Proximity Tripwire)
	t1 := t0.Add(24 * time.Hour)
	prDiff := anomaly.DiffReport{
		BaseCommit: "commit-1",
		HeadCommit: "commit-2",
		Added: []airom.Component{
			{
				Name: "UnapprovedHiringModel",
				PURL: "pkg:pypi/unapproved-recruiter@1.0.0",
				Evidence: airom.Evidence{
					Occurrences: []airom.Occurrence{
						{Location: airom.Location{Path: "src/hiring/applicant_scorer.py"}},
					},
				},
			},
		},
	}

	anomalyReport := anomaly.EvaluateAnomalies(prDiff, nil)
	if anomalyReport.Clean || len(anomalyReport.Anomalies) == 0 {
		t.Fatalf("expected anomalies detected by AnomalyEngine on unapproved hiring model")
	}

	// Translate findings into ComplianceDB evaluations
	snap1 := NewSnapshot(
		"snap-1",
		repoID,
		"commit-2",
		"main",
		t1,
		"aibom-sha-commit2",
		13,
		0,
		3,
		1, // NYC LL144 gap triggered by hiring proximity
		0,
		snap0.SelfHash,
		json.RawMessage(`{"components": [{"name": "approved-core"}, {"name": "UnapprovedHiringModel"}]}`),
	)

	evals1 := []ControlEvaluation{
		{ID: "ev-1-1", SnapshotID: snap1.ID, ControlID: "co.ai-act.impact-assessment", StatuteRef: "CO SB 24-205", Verdict: VerdictMet},
		{ID: "ev-1-2", SnapshotID: snap1.ID, ControlID: "nyc.ll144.bias-audit", StatuteRef: "NYC LL144", Verdict: VerdictGap, GapMessage: "Unapproved hiring component detected in applicant_scorer.py"},
	}

	newIncs1, resolvedIncs1, activeIncs1 := ProcessSnapshotIncidents(activeIncs0, snap1, evals1)
	if len(newIncs1) != 1 || len(activeIncs1) != 1 || len(resolvedIncs1) != 0 {
		t.Fatalf("expected 1 new incident opened for NYC LL144 gap and 0 resolved, got %d new, %d resolved", len(newIncs1), len(resolvedIncs1))
	}
	if newIncs1[0].ControlID != "nyc.ll144.bias-audit" {
		t.Errorf("expected incident control nyc.ll144.bias-audit, got %s", newIncs1[0].ControlID)
	}

	// Step 3: Scan 3 (Remediation PR: Model audited & approved)
	t2 := t0.Add(72 * time.Hour)
	snap2 := NewSnapshot(
		"snap-2",
		repoID,
		"commit-3",
		"main",
		t2,
		"aibom-sha-commit3",
		13,
		0,
		4,
		0,
		0,
		snap1.SelfHash,
		json.RawMessage(`{"components": [{"name": "approved-core"}, {"name": "AuditedHiringModel"}]}`),
	)

	evals2 := []ControlEvaluation{
		{ID: "ev-2-1", SnapshotID: snap2.ID, ControlID: "co.ai-act.impact-assessment", StatuteRef: "CO SB 24-205", Verdict: VerdictMet},
		{ID: "ev-2-2", SnapshotID: snap2.ID, ControlID: "nyc.ll144.bias-audit", StatuteRef: "NYC LL144", Verdict: VerdictMet},
	}

	newIncs2, resolvedIncs2, activeIncs2 := ProcessSnapshotIncidents(activeIncs1, snap2, evals2)
	if len(newIncs2) != 0 || len(resolvedIncs2) != 1 || len(activeIncs2) != 0 {
		t.Fatalf("expected 1 incident resolved and 0 remaining open, got %d resolved and %d open", len(resolvedIncs2), len(activeIncs2))
	}

	// Verify resolution duration: t2 - t1 = 48 hours
	if *resolvedIncs2[0].ResolutionDurationHours != 48.0 {
		t.Errorf("expected 48.0 resolution hours, got %f", *resolvedIncs2[0].ResolutionDurationHours)
	}

	// Step 4: Validate immutable cryptographic chain integrity across entire pipeline
	chainReport := ValidateChain([]ScanSnapshot{snap0, snap1, snap2})
	if !chainReport.Valid {
		t.Fatalf("expected pipeline hash chain to be valid, got broken at %d: %s", chainReport.BrokenAtIndex, chainReport.Reason)
	}
	if chainReport.TotalSnapshots != 3 {
		t.Errorf("expected 3 snapshots in chain report, got %d", chainReport.TotalSnapshots)
	}
}
