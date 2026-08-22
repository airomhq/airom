package report

import (
	"encoding/json"
	"time"

	"github.com/airomhq/airom/services/compliancedb"
)

// EvidenceKey format is "path:line" or "aibom_id:path:line".
type EvidenceKey = string

// EvidenceRef represents a verified ground-truth occurrence in the codebase.
type EvidenceRef struct {
	AIBOMID     string  `json:"aibom_id"`
	FilePath    string  `json:"file_path"`
	LineNumber  int     `json:"line_number"`
	ComponentID string  `json:"component_id"`
	ModelName   string  `json:"model_name"`
	Kind        string  `json:"kind"`
	Confidence  float64 `json:"confidence"`
	Snippet     string  `json:"snippet,omitempty"`
}

// Key returns the canonical lookup key "filePath:lineNumber".
func (e EvidenceRef) Key() EvidenceKey {
	return FormatEvidenceKey(e.FilePath, e.LineNumber)
}

// FullKey returns "aibom_id:filePath:lineNumber".
func (e EvidenceRef) FullKey() string {
	return e.AIBOMID + ":" + e.Key()
}

// Citation records an extracted [ev:...] reference.
type Citation struct {
	RawTag        string       `json:"raw_tag"`
	AIBOMID       string       `json:"aibom_id"`
	FilePath      string       `json:"file_path"`
	LineNumber    int          `json:"line_number"`
	IsValid       bool         `json:"is_valid"`
	ValidationMsg string       `json:"validation_msg,omitempty"`
	Evidence      *EvidenceRef `json:"evidence,omitempty"`
}

// AttestationStatus indicates the verification state of a report section.
type AttestationStatus string

const (
	StatusVerified               AttestationStatus = "VERIFIED"
	StatusRequiresAttestation    AttestationStatus = "REQUIRES_MANUAL_ATTESTATION"
	StatusInvalidCitationRemoved AttestationStatus = "INVALID_CITATION_REMOVED"
)

// ReportSection represents a distinct heading and body within a compliance document.
type ReportSection struct {
	ID                string            `json:"id"`
	Title             string            `json:"title"`
	Prose             string            `json:"prose"`
	Citations         []Citation        `json:"citations"`
	AttestationStatus AttestationStatus `json:"attestation_status"`
	StatuteRef        string            `json:"statute_ref,omitempty"`
}

// ComplianceReport is the top-level structured output of the ReportEngine.
type ComplianceReport struct {
	ID                string                           `json:"id"`
	Framework         string                           `json:"framework"` // e.g. "colorado-ai-act", "nyc-ll144", "ca-ab2013"
	Title             string                           `json:"title"`
	OrgName           string                           `json:"org_name"`
	RepoName          string                           `json:"repo_name"`
	CommitSHA         string                           `json:"commit_sha"`
	GeneratedAt       time.Time                        `json:"generated_at"`
	ExecutiveSummary  string                           `json:"executive_summary"`
	Sections          []ReportSection                  `json:"sections"`
	Evaluations       []compliancedb.ControlEvaluation `json:"evaluations"`
	AllCitationsValid bool                             `json:"all_citations_valid"`
	SignerName        string                           `json:"signer_name,omitempty"`
	SignerTitle       string                           `json:"signer_title,omitempty"`
	Metadata          map[string]string                `json:"metadata,omitempty"`
}

// ReportRequest is the input payload to generate a report.
type ReportRequest struct {
	OrgID         string                           `json:"org_id"`
	OrgName       string                           `json:"org_name"`
	RepoID        string                           `json:"repo_id"`
	RepoName      string                           `json:"repo_name"`
	CommitSHA     string                           `json:"commit_sha"`
	Framework     string                           `json:"framework"`
	Snapshot      *compliancedb.ScanSnapshot       `json:"snapshot,omitempty"`
	Evaluations   []compliancedb.ControlEvaluation `json:"evaluations,omitempty"`
	EvidenceIndex map[EvidenceKey]EvidenceRef      `json:"evidence_index,omitempty"`
	SignerName    string                           `json:"signer_name,omitempty"`
	SignerTitle   string                           `json:"signer_title,omitempty"`
	RawAIBOM      json.RawMessage                  `json:"raw_aibom,omitempty"`
}

// VerifiedProseResult holds the output of the AST citation verification.
type VerifiedProseResult struct {
	CleanedProse       string            `json:"cleaned_prose"`
	ExtractedCitations []Citation        `json:"extracted_citations"`
	ValidCount         int               `json:"valid_count"`
	InvalidCount       int               `json:"invalid_count"`
	UncitedClaims      int               `json:"uncited_claims"`
	AttestationStatus  AttestationStatus `json:"attestation_status"`
}
