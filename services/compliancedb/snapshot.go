package compliancedb

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// ComputeSnapshotHash generates a deterministic SHA-256 cryptographic hash
// binding the repository, commit, scan timestamp, AIBOM sha, compliance metrics, and parent hash.
func ComputeSnapshotHash(
	repoID string,
	commitSHA string,
	ts time.Time,
	aibomSHA string,
	met, gap, manual int,
	prevHash string,
) string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%s|%d:%d:%d|%s",
		repoID,
		commitSHA,
		ts.UTC().Format(time.RFC3339),
		aibomSHA,
		met, gap, manual,
		prevHash,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// NewSnapshot constructs a ScanSnapshot and generates its cryptographic self_hash.
func NewSnapshot(
	id string,
	repoID string,
	commitSHA string,
	branch string,
	ts time.Time,
	aibomSHA string,
	compCount int,
	vulnCount int,
	met, gap, manual int,
	prevHash string,
	rawAIBOM json.RawMessage,
) ScanSnapshot {
	selfHash := ComputeSnapshotHash(repoID, commitSHA, ts, aibomSHA, met, gap, manual, prevHash)
	return ScanSnapshot{
		ID:                   id,
		RepoID:               repoID,
		CommitSHA:            commitSHA,
		Branch:               branch,
		ScanTimestamp:        ts.UTC(),
		AIBOMSHA256:          aibomSHA,
		ComponentsCount:      compCount,
		VulnerabilitiesCount: vulnCount,
		ControlsMet:          met,
		ControlsGap:          gap,
		ControlsManual:       manual,
		PrevSnapshotHash:     prevHash,
		SelfHash:             selfHash,
		RawAIBOM:             rawAIBOM,
	}
}

// VerifySnapshot checks whether a single snapshot's self_hash matches its computed hash.
func VerifySnapshot(s ScanSnapshot) bool {
	expected := ComputeSnapshotHash(
		s.RepoID,
		s.CommitSHA,
		s.ScanTimestamp,
		s.AIBOMSHA256,
		s.ControlsMet,
		s.ControlsGap,
		s.ControlsManual,
		s.PrevSnapshotHash,
	)
	return expected == s.SelfHash
}

// ValidateChain verifies the cryptographic integrity and chronological consistency of a chain of snapshots.
// Returns a report detailing whether the chain is intact, or pinpointing the exact index and reason for tampering.
func ValidateChain(chain []ScanSnapshot) ChainVerificationReport {
	if len(chain) == 0 {
		return ChainVerificationReport{
			Valid:          true,
			TotalSnapshots: 0,
			BrokenAtIndex:  -1,
		}
	}

	var violations []string

	for i, s := range chain {
		// 1. Verify internal self hash integrity
		if !VerifySnapshot(s) {
			reason := fmt.Sprintf("snapshot %d (%s) self_hash mismatch: computed hash does not match self_hash", i, s.ID)
			violations = append(violations, reason)
			idCopy := s.ID
			return ChainVerificationReport{
				Valid:          false,
				TotalSnapshots: len(chain),
				BrokenAtIndex:  i,
				BrokenSnapshot: &idCopy,
				Reason:         reason,
				Violations:     violations,
			}
		}

		// 2. For subsequent nodes, verify parent hash continuity and time monotonicity
		if i > 0 {
			prev := chain[i-1]
			if s.PrevSnapshotHash != prev.SelfHash {
				reason := fmt.Sprintf("snapshot %d (%s) prev_snapshot_hash %q does not match previous snapshot self_hash %q", i, s.ID, s.PrevSnapshotHash, prev.SelfHash)
				violations = append(violations, reason)
				idCopy := s.ID
				return ChainVerificationReport{
					Valid:          false,
					TotalSnapshots: len(chain),
					BrokenAtIndex:  i,
					BrokenSnapshot: &idCopy,
					Reason:         reason,
					Violations:     violations,
				}
			}

			if s.ScanTimestamp.Before(prev.ScanTimestamp) {
				reason := fmt.Sprintf("snapshot %d (%s) scan_timestamp (%s) is earlier than previous snapshot (%s)", i, s.ID, s.ScanTimestamp.Format(time.RFC3339), prev.ScanTimestamp.Format(time.RFC3339))
				violations = append(violations, reason)
				idCopy := s.ID
				return ChainVerificationReport{
					Valid:          false,
					TotalSnapshots: len(chain),
					BrokenAtIndex:  i,
					BrokenSnapshot: &idCopy,
					Reason:         reason,
					Violations:     violations,
				}
			}
		}
	}

	return ChainVerificationReport{
		Valid:          true,
		TotalSnapshots: len(chain),
		BrokenAtIndex:  -1,
	}
}

// ProcessSnapshotIncidents updates open compliance incidents against a new scan snapshot's control evaluations.
// If a control reports a gap, an incident is opened (if not already open).
// If a previously gapped control reports met, the incident is marked RESOLVED and duration hours are recorded.
func ProcessSnapshotIncidents(
	existingOpenIncidents []ComplianceIncident,
	snapshot ScanSnapshot,
	evaluations []ControlEvaluation,
) (newIncidents []ComplianceIncident, resolvedIncidents []ComplianceIncident, remainingOpen []ComplianceIncident) {
	openByControl := make(map[string]ComplianceIncident)
	for _, inc := range existingOpenIncidents {
		if inc.Status == IncidentStatusOpen {
			openByControl[inc.ControlID] = inc
		}
	}

	evalByControl := make(map[string]ControlEvaluation)
	for _, ev := range evaluations {
		evalByControl[ev.ControlID] = ev
	}

	// 1. Process control evaluations
	for _, ev := range evaluations {
		existing, hasOpen := openByControl[ev.ControlID]

		if ev.Verdict == VerdictGap {
			if !hasOpen {
				// Open new incident
				inc := ComplianceIncident{
					ID:                fmt.Sprintf("inc-%s-%d", ev.ControlID, snapshot.ScanTimestamp.UnixNano()),
					RepoID:            snapshot.RepoID,
					ControlID:         ev.ControlID,
					StatuteRef:        ev.StatuteRef,
					Status:            IncidentStatusOpen,
					OpenedAt:          snapshot.ScanTimestamp,
					OpeningSnapshotID: snapshot.ID,
				}
				newIncidents = append(newIncidents, inc)
				openByControl[ev.ControlID] = inc
			}
		} else if ev.Verdict == VerdictMet {
			if hasOpen {
				// Resolve existing incident
				resolved := existing
				resolved.Status = IncidentStatusResolved
				resTime := snapshot.ScanTimestamp
				resolved.ResolvedAt = &resTime
				resSnapID := snapshot.ID
				resolved.ResolvingSnapshotID = &resSnapID
				
				hours := resTime.Sub(existing.OpenedAt).Hours()
				resolved.ResolutionDurationHours = &hours

				resolvedIncidents = append(resolvedIncidents, resolved)
				delete(openByControl, ev.ControlID)
			}
		}
	}

	for _, inc := range openByControl {
		remainingOpen = append(remainingOpen, inc)
	}

	return newIncidents, resolvedIncidents, remainingOpen
}
