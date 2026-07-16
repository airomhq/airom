package detect

import "github.com/Roro1727/airom/pkg/airom"

// ModelClaim is the partial model facet a detector may assert. Plain values
// — the assembler converts to tri-state facet fields, merges across
// detectors (Known > Unknown > Absent), and demotes conflicts (§9.2).
type ModelClaim struct {
	Task          string
	Architecture  string
	ParamCount    int64 // 0 = unclaimed
	Quantization  string
	ContextLength int64 // 0 = unclaimed
	Format        string
	BaseModel     string
	PickleRisk    *airom.PickleRisk
	Card          *airom.ModelCard
}

// DataClaim is the partial dataset/prompt facet.
type DataClaim struct {
	Format    string
	SizeBytes int64 // 0 = unclaimed
	URL       string
}

// InfraClaim is the partial serving-infrastructure facet.
type InfraClaim struct {
	Endpoint   string
	Region     string
	Deployment string
}

// PackageClaim is the partial framework/library facet.
type PackageClaim struct {
	Ecosystem string // pypi|npm|golang|maven|cargo|nuget
}

// ComponentClaim is what a detector asserts about a component: raw,
// un-normalized, identity-free. The assembler — never the detector — mints
// IDs, normalizes names, derives purls, dedups, and merges (invariant P4).
type ComponentClaim struct {
	Kind     airom.ComponentKind
	Name     string // raw as-seen; the assembler normalizes
	Group    string
	Version  string // raw version claim; "" = unknown (folding law, §9.1)
	Provider string

	Licenses         []airom.License
	Hashes           []airom.Hash // e.g. digests parsed from a lockfile; the engine adds content hashes itself
	DownloadLocation string

	// Exactly one facet claim per kind family (validated at assembly).
	Model   *ModelClaim
	Data    *DataClaim
	Infra   *InfraClaim
	Package *PackageClaim
}

// TargetHint names a relation's target for the assembler to resolve AFTER
// all components exist (§6.1). Exactly one form is set:
//
//   - Kind+Name: a concrete target name.
//   - Kind+FromField: the target's name is the occurrence field's value
//     (e.g. the "model" named group captured at the same call site).
//   - LocalRef: the claim another finding by the same detector made in the
//     same file (referenced by that finding's DetectorID or rule ID).
//
// A hint that resolves to nothing becomes a warning in Inventory.Stats —
// never a phantom node, never a guessed edge.
type TargetHint struct {
	Kind      airom.ComponentKind
	Name      string
	FromField string
	LocalRef  string
}

// RelationClaim is an edge claim: from the finding's component to the
// resolved target.
type RelationClaim struct {
	Type   airom.RelType
	Target TargetHint
}

// Finding is one claim about one component at one location — the unit of
// detector output.
type Finding struct {
	Claim      ComponentClaim
	Occurrence airom.Occurrence
	Relations  []RelationClaim
}

// FindingsView is the immutable phase-1 findings snapshot every
// ProjectDetector receives. Accessors return shared slices — treat them as
// read-only.
type FindingsView struct {
	all    []Finding
	byPath map[string][]Finding
}

// NewFindingsView builds a view over phase-1 findings.
func NewFindingsView(findings []Finding) *FindingsView {
	v := &FindingsView{all: findings, byPath: make(map[string][]Finding)}
	for _, f := range findings {
		p := f.Occurrence.Location.Path
		v.byPath[p] = append(v.byPath[p], f)
	}
	return v
}

// All returns every phase-1 finding.
func (v *FindingsView) All() []Finding { return v.all }

// ForPath returns the findings located in one file.
func (v *FindingsView) ForPath(path string) []Finding { return v.byPath[path] }

// ByKind returns the findings claiming a given component kind.
func (v *FindingsView) ByKind(kind airom.ComponentKind) []Finding {
	var out []Finding
	for _, f := range v.all {
		if f.Claim.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

// ByDetector returns the findings a given detector produced.
func (v *FindingsView) ByDetector(id string) []Finding {
	var out []Finding
	for _, f := range v.all {
		if f.Occurrence.DetectorID == id {
			out = append(out, f)
		}
	}
	return out
}
