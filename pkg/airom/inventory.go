package airom

import "time"

// RelType is a typed relationship between components (§5). The graph is a
// first-class citizen: SPDX 3.0 demands one, and edges carry their own
// evidence and confidence.
type RelType string

// The ten relationship types.
const (
	RelUses        RelType = "uses"         // app USES hosted-llm
	RelDependsOn   RelType = "depends-on"   // app DEPENDS_ON framework (manifest)
	RelServedBy    RelType = "served-by"    // model SERVED_BY infra
	RelQueries     RelType = "queries"      // retriever QUERIES vector-db
	RelEmbedsWith  RelType = "embeds-with"  // rag-pipeline EMBEDS_WITH embedding-model
	RelPromptedBy  RelType = "prompted-by"  // hosted-llm PROMPTED_BY prompt
	RelTrainedOn   RelType = "trained-on"   // model TRAINED_ON dataset (SPDX trainedOn)
	RelDerivedFrom RelType = "derived-from" // LoRA adapter DERIVED_FROM base model
	RelConfigures  RelType = "configures"   // config file CONFIGURES model/infra
	RelContains    RelType = "contains"     // rag-pipeline CONTAINS retriever/store
)

// Relationship is an evidenced, typed edge: the call site proving the edge
// travels with it, not just the endpoints.
type Relationship struct {
	From       ID           `json:"from"`
	To         ID           `json:"to"`
	Type       RelType      `json:"type"`
	Confidence Confidence   `json:"confidence"`
	Evidence   []Occurrence `json:"evidence,omitempty"`
}

// Unknown records "looked relevant, could not process" — honesty over
// silence (invariant P6). DetectorID is the failing detector when known, or
// a pipeline stage label ("walk", "header", "process").
type Unknown struct {
	Path       string `json:"path"`
	DetectorID string `json:"detectorId"`
	Reason     string `json:"reason"`
}

// ToolInfo identifies the producing tool — embedded in every AIBOM and
// printed by `airom version`.
type ToolInfo struct {
	Name    string `json:"name"` // "airom"
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

// GitInfo is repository provenance for repo-backed scans.
type GitInfo struct {
	Remote string `json:"remote,omitempty"`
	Commit string `json:"commit,omitempty"`
	Branch string `json:"branch,omitempty"`
	Dirty  bool   `json:"dirty,omitempty"`
}

// K8sInfo is cluster provenance for k8s scans.
type K8sInfo struct {
	Context    string   `json:"context,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
}

// SourceInfo is the provenance root: what was scanned (§7).
type SourceInfo struct {
	Kind        string   `json:"kind"` // dir | repo | image | k8s
	Target      string   `json:"target"`
	ImageDigest string   `json:"imageDigest,omitempty"`
	Git         *GitInfo `json:"git,omitempty"`
	K8s         *K8sInfo `json:"k8s,omitempty"`
}

// DetectorStat is one detector's runtime accounting (--stats).
type DetectorStat struct {
	ID          string `json:"id"`
	Invocations int64  `json:"invocations"`
	Findings    int64  `json:"findings"`
	NS          int64  `json:"ns"` // cumulative nanoseconds; normalized in goldens (P7)
}

// ScanStats is the honesty block (§14): what the scan looked at, skipped,
// and spent — "what did the scanner NOT see" is always answerable. Timing
// fields are legitimately nondeterministic; writers normalize them to keep
// the P7 byte-identical contract.
type ScanStats struct {
	FilesWalked    int64          `json:"filesWalked"`
	FilesProcessed int64          `json:"filesProcessed"`
	FilesFailed    int64          `json:"filesFailed"`
	HeaderBytes    int64          `json:"headerBytes"`
	ContentBytes   int64          `json:"contentBytes"`
	Duration       time.Duration  `json:"durationNs"`
	Selection      []string       `json:"selection,omitempty"` // which expression enabled which detector (§6.2)
	Detectors      []DetectorStat `json:"detectors,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"` // e.g. dangling relation hints (§9.2)
}

// Inventory is THE document: the assembled component graph every writer
// serializes (invariant P5). The native JSON serialization of this struct
// is a versioned API from release one.
type Inventory struct {
	SchemaVersion string         `json:"schemaVersion"` // "1"
	Tool          ToolInfo       `json:"tool"`
	Serial        string         `json:"serial"`    // uuid → CDX serialNumber (injectable for goldens)
	Timestamp     time.Time      `json:"timestamp"` // injectable clock
	Lifecycle     string         `json:"lifecycle"` // "pre-build" (source) | "post-build" (image)
	Source        SourceInfo     `json:"source"`
	Root          ID             `json:"root"`
	Components    []Component    `json:"components"`              // sorted by ID — deterministic
	Relationships []Relationship `json:"relationships,omitempty"` // sorted (From, Type, To)
	Unknowns      []Unknown      `json:"unknowns,omitempty"`
	Stats         ScanStats      `json:"stats"`
}
