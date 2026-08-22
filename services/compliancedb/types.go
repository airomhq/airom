package compliancedb

import (
	"encoding/json"
	"time"
)

// Verdict values for control evaluations.
const (
	VerdictMet    = "met"
	VerdictGap    = "gap"
	VerdictManual = "manual"
)

// Incident status values.
const (
	IncidentStatusOpen     = "OPEN"
	IncidentStatusResolved = "RESOLVED"
)

// Organization represents an enterprise tenant in ComplianceDB.
type Organization struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// Repository represents a tracked codebase repository.
type Repository struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"orgId"`
	GitURL        string    `json:"gitUrl"`
	DefaultBranch string    `json:"defaultBranch"`
	CreatedAt     time.Time `json:"createdAt"`
}

// ScanSnapshot is an immutable, hash-chained record of a repository compliance scan.
type ScanSnapshot struct {
	ID                   string          `json:"id"`
	RepoID               string          `json:"repoId"`
	CommitSHA            string          `json:"commitSha"`
	Branch               string          `json:"branch"`
	ScanTimestamp        time.Time       `json:"scanTimestamp"`
	AIBOMSHA256          string          `json:"aibomSha256"`
	ComponentsCount      int             `json:"componentsCount"`
	VulnerabilitiesCount int             `json:"vulnerabilitiesCount"`
	ControlsMet          int             `json:"controlsMet"`
	ControlsGap          int             `json:"controlsGap"`
	ControlsManual       int             `json:"controlsManual"`
	PrevSnapshotHash     string          `json:"prevSnapshotHash"`
	SelfHash             string          `json:"selfHash"`
	RawAIBOM             json.RawMessage `json:"rawAibom,omitempty"`
}

// ControlEvaluation records the outcome of a single compliance control assessment.
type ControlEvaluation struct {
	ID             string    `json:"id"`
	SnapshotID     string    `json:"snapshotId"`
	ControlID      string    `json:"controlId"`
	StatuteRef     string    `json:"statuteRef"`
	Verdict        string    `json:"verdict"` // met, gap, manual
	GapMessage     string    `json:"gapMessage,omitempty"`
	RemediationURL string    `json:"remediationUrl,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

// ComplianceIncident tracks a compliance gap lifecycle from detection to resolution.
type ComplianceIncident struct {
	ID                      string     `json:"id"`
	RepoID                  string     `json:"repoId"`
	ControlID               string     `json:"controlId"`
	StatuteRef              string     `json:"statuteRef"`
	Status                  string     `json:"status"` // OPEN, RESOLVED
	OpenedAt                time.Time  `json:"openedAt"`
	OpeningSnapshotID       string     `json:"openingSnapshotId"`
	ResolvedAt              *time.Time `json:"resolvedAt,omitempty"`
	ResolvingSnapshotID     *string    `json:"resolvingSnapshotId,omitempty"`
	ResolutionDurationHours *float64   `json:"resolutionDurationHours,omitempty"`
}

// FilingAuditLog records regulatory interactions and attestations.
type FilingAuditLog struct {
	ID           string          `json:"id"`
	RepoID       string          `json:"repoId"`
	RegulationID string          `json:"regulationId"`
	Action       string          `json:"action"`
	Actor        string          `json:"actor"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	Timestamp    time.Time       `json:"timestamp"`
}

// ChainVerificationReport contains detailed integrity diagnostic results of a snapshot chain.
type ChainVerificationReport struct {
	Valid          bool     `json:"valid"`
	TotalSnapshots int      `json:"totalSnapshots"`
	BrokenAtIndex  int      `json:"brokenAtIndex"` // -1 if valid
	BrokenSnapshot *string  `json:"brokenSnapshot,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	Violations     []string `json:"violations,omitempty"`
}
