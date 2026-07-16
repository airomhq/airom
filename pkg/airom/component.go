package airom

// ── Evidence: the Occurrence is the atom (§5) ───────────────────────────────

// Location is where evidence physically sits. Path is always set,
// source-root-relative with forward slashes. Lines are 1-based (0 =
// whole-file); columns are 1-based UTF-16 code units (SARIF's columnKind,
// decision D18); Layer is the OCI layer digest when attributable.
type Location struct {
	Path      string `json:"path"`
	Line      int    `json:"line,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	Column    int    `json:"column,omitempty"`
	EndColumn int    `json:"endColumn,omitempty"`
	Layer     string `json:"layer,omitempty"`
}

// Occurrence is one sighting of a component by one detector — the answer to
// "why is this in my AIBOM?". It maps to CycloneDX evidence.occurrences[]
// and one SARIF result.
type Occurrence struct {
	Location   Location          `json:"location"`
	DetectorID string            `json:"detectorId"` // stable; SARIF ruleId ("rules/openai/model-literal")
	Method     DetectionMethod   `json:"method"`
	Confidence Confidence        `json:"confidence"`        // this sighting alone
	Snippet    string            `json:"snippet,omitempty"` // matched text, ≤200 bytes, sanitized
	Symbol     string            `json:"symbol,omitempty"`  // enclosing func/class if known
	Fields     map[string]string `json:"fields,omitempty"`  // extracted bindings: {"model":"gpt-4.1","temperature":"0.2"}
}

// IdentityClaim preserves contested per-field identity — never silently
// discarded (§9.2). A version from a lockfile (0.95) beats one from a code
// comment (0.3); the loser is retained here and emitted as a competing
// CycloneDX evidence.identity[] entry.
type IdentityClaim struct {
	Field      string            `json:"field"` // name | version | purl | hash (CDX identity field enum)
	Value      string            `json:"value"`
	Confidence Confidence        `json:"confidence"`
	Methods    []DetectionMethod `json:"methods,omitempty"`
}

// Evidence is a component's accumulated proof.
type Evidence struct {
	Occurrences []Occurrence    `json:"occurrences,omitempty"`
	Identity    []IdentityClaim `json:"identity,omitempty"`
}

// ── Supporting value types ──────────────────────────────────────────────────

// Hash is a named digest ("SHA-256" + lowercase hex).
type Hash struct {
	Alg string `json:"alg"`
	Hex string `json:"hex"`
}

// KV is an overflow property, emitted under the airom:* CycloneDX property
// namespace (docs/mapping.md).
type KV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// License identifies a license by SPDX ID, free-form name, or SPDX
// expression — exactly one field is normally set.
type License struct {
	SPDXID     string `json:"spdxId,omitempty"`
	Name       string `json:"name,omitempty"`
	Expression string `json:"expression,omitempty"`
}

// Party is a supplier/author reference (CDX supplier, SPDX suppliedBy).
type Party struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// AttestationRef is a discovered (v1) or verified (v2) attestation:
// reserved slots so Sigstore/SLSA verification lands with zero model
// changes (§16).
type AttestationRef struct {
	Type     string   `json:"type"` // "sigstore-bundle","slsa-provenance","in-toto"
	URI      string   `json:"uri,omitempty"`
	Digest   Hash     `json:"digest,omitempty"`
	Verified TriState `json:"verified"`
}

// ── Facets (§5): exactly one non-nil per kind family ────────────────────────

// BoundParam is a generation parameter with its own provenance. Two call
// sites with different temperatures are two BoundParams — never merged,
// never averaged (§9.5).
type BoundParam struct {
	Name       string      `json:"name"`  // "temperature"
	Value      string      `json:"value"` // "0.2"
	Occurrence *Occurrence `json:"occurrence,omitempty"`
}

// PickleRisk records suspicious GLOBAL opcodes found by the static pickle
// walk (§13) — surfaced as a security signal, never executed.
type PickleRisk struct {
	Globals []string `json:"globals"` // dotted callables: "os.system", "builtins.eval"
}

// PerformanceMetric is one modelCard quantitative-analysis entry.
type PerformanceMetric struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Slice string `json:"slice,omitempty"`
}

// EnergyConsumption is one modelCard environmental entry.
type EnergyConsumption struct {
	Activity string  `json:"activity"` // "training","inference"
	KWh      float64 `json:"kWh"`
}

// Considerations mirrors the CycloneDX modelCard considerations block.
type Considerations struct {
	Users                []string `json:"users,omitempty"`
	UseCases             []string `json:"useCases,omitempty"`
	TechnicalLimitations []string `json:"technicalLimitations,omitempty"`
}

// ModelCard is the CycloneDX modelCard superset (§5): populated when a
// source (HF config, model_index, embedded card) provides it.
type ModelCard struct {
	Metrics        []PerformanceMetric `json:"metrics,omitempty"`
	Considerations *Considerations     `json:"considerations,omitempty"`
	Energy         []EnergyConsumption `json:"energy,omitempty"`
}

// ModelFacet carries model-shaped data for hosted-llm, local-model-file,
// and embedding-model components. Maps onto CycloneDX modelCard and SPDX
// ai_AIPackage (docs/mapping.md).
type ModelFacet struct {
	Task             OptString    `json:"task,omitzero"`         // "text-generation","embedding","rerank"
	Architecture     OptString    `json:"architecture,omitzero"` // gguf general.architecture / config.json model_type
	ParamCount       OptInt64     `json:"paramCount,omitzero"`   // exact, from GGUF/safetensors headers
	Quantization     OptString    `json:"quantization,omitzero"` // "Q4_K_M","F16"
	ContextLength    OptInt64     `json:"contextLength,omitzero"`
	Format           OptString    `json:"format,omitzero"`    // "gguf","safetensors","onnx",…
	BaseModel        OptString    `json:"baseModel,omitzero"` // adapter lineage → also a derived-from edge
	GenerationParams []BoundParam `json:"generationParams,omitempty"`
	PickleRisk       *PickleRisk  `json:"pickleRisk,omitempty"`
	Card             *ModelCard   `json:"card,omitempty"`
}

// DataFacet carries dataset/prompt-shaped data.
type DataFacet struct {
	Format    OptString `json:"format,omitzero"` // csv|jsonl|parquet|arrow|hf-dataset|kaggle|prompt-template
	SizeBytes OptInt64  `json:"sizeBytes,omitzero"`
	URL       OptString `json:"url,omitzero"`
}

// InfraFacet carries serving-infrastructure data for infra and service
// components.
type InfraFacet struct {
	Endpoint   OptString `json:"endpoint,omitzero"`
	Region     OptString `json:"region,omitzero"`
	Deployment OptString `json:"deployment,omitzero"`
}

// PackageFacet carries framework/library package data.
type PackageFacet struct {
	Ecosystem string `json:"ecosystem,omitempty"` // pypi|npm|golang|maven|cargo|nuget
}

// ── Component (§5) ──────────────────────────────────────────────────────────

// Component is one discovered AI asset: canonical identity, provenance,
// exactly one kind-family facet, assembled confidence, and the evidence
// behind every claim. Satisfies the required schema field-for-field
// (name/type/version/provider/source/location/framework/license/provenance/
// checksum/confidence/detection-method/metadata).
type Component struct {
	ID       ID            `json:"id"`
	Kind     ComponentKind `json:"kind"`
	Name     string        `json:"name"`            // canonical, post-normalization
	Group    string        `json:"group,omitempty"` // org/namespace: "openai", "meta-llama"
	Version  OptString     `json:"version,omitzero"`
	Provider OptString     `json:"provider,omitzero"`
	PURL     string        `json:"purl,omitempty"` // spec types ONLY; empty for hosted API models (D9)
	Licenses []License     `json:"licenses,omitempty"`
	Supplier *Party        `json:"supplier,omitempty"`

	// Provenance & integrity
	Hashes           []Hash    `json:"hashes,omitempty"` // always computed for local model files
	DownloadLocation OptString `json:"downloadLocation,omitzero"`
	SourceInfo       string    `json:"sourceInfo,omitempty"` // human trail: "declared in requirements.txt; loaded in src/rag.py"
	ReleaseTime      OptTime   `json:"releaseTime,omitzero"`

	// Facets — exactly one non-nil per kind family (assembler-validated)
	Model   *ModelFacet   `json:"model,omitempty"`
	Data    *DataFacet    `json:"data,omitempty"`
	Infra   *InfraFacet   `json:"infra,omitempty"`
	Package *PackageFacet `json:"package,omitempty"`

	Confidence Confidence `json:"confidence"` // assembled (§9.3) — never detector-set
	Evidence   Evidence   `json:"evidence"`
	Props      []KV       `json:"props,omitempty"` // overflow → CDX properties, airom:* namespace

	Attestations []AttestationRef `json:"attestations,omitempty"`
}
