// Package spdxw writes an SPDX 3.0.1 document with the AI, Dataset, Software,
// and Security profiles.
//
// The mapping is not invented here: docs/mapping.md is the authoritative
// field-mapping law and carries a fully specified SPDX 3.0.1 column, including
// the per-kind element classes (§4), the tri-state NOASSERTION discipline
// (§6.4), and the relationship vocabulary (§3.10). This writer implements that
// column; where the two ever disagree, mapping.md is right and this is a bug.
//
// SPDX is the lossiest of AIROM's formats and mapping.md says so explicitly.
// The largest loss is Evidence — SPDX 3.0.1 has no home for "seen at file:line
// by technique T with confidence C", which is the thing AIROM exists to record.
// Anyone who needs that should take CycloneDX or the native JSON; SPDX is here
// because SPDX is what a lot of downstream tooling ingests, not because it is
// the best carrier for this graph.
//
// Where a field has no SPDX home, it goes into the element `comment` under an
// `airom:` prefix rather than being dropped. That is not a real mapping and no
// consumer will understand it, but P6 says a reader must never mistake silence
// for absence, and a comment a human can read beats a value that vanished.
package spdxw

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

func init() {
	writer.Register(format, func(o writer.Options) writer.Writer { return New(o) })
}

const (
	format = "spdx"

	specVersion = "3.0.1"
	contextIRI  = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

	// noAssertion is the scalar sentinel for an Unknown or coarsened-Absent
	// required field (§6.4).
	noAssertion = "NOASSERTION"

	// noAssertionElement is the core individual used where a field takes an
	// ELEMENT reference rather than a scalar — suppliedBy and originatedBy,
	// chiefly (§6.4).
	noAssertionElement = "https://spdx.org/rdf/3.0.1/terms/Core/NoAssertionElement"

	// noAssertionDatasetType is the enum member (not the scalar sentinel) that
	// dataset_datasetType uses, because that field is a controlled vocabulary
	// with 1..* cardinality: it cannot be omitted and cannot take a free
	// string.
	noAssertionDatasetType = "noAssertion"

	// creationInfoRef is the blank node every element points at. One shared
	// CreationInfo keeps the graph small and is what §3.1 specifies.
	creationInfoRef = "_:creationInfo"

	// docNamespace is the IRI prefix for element identifiers. mapping.md left
	// this "finalized with the v2 writer", so it is finalized here.
	//
	// It deliberately does NOT use airom.dev, which mapping.md's example shows:
	// that domain is unregistered and belongs to nobody, and minting
	// identifiers under a namespace the project does not control is bad
	// practice even though an SPDX namespace is an identifier that never has
	// to resolve.
	docNamespace = "https://github.com/airomhq/airom/spdxdocs/"
)

// Writer renders an Inventory as SPDX 3.0.1 JSON-LD.
type Writer struct{ opts writer.Options }

// New constructs the SPDX writer.
func New(o writer.Options) Writer { return Writer{opts: o} }

// Format implements writer.Writer.
func (Writer) Format() string { return format }

// document is the JSON-LD envelope: a context plus a flat element graph.
type document struct {
	Context string `json:"@context"`
	Graph   []any  `json:"@graph"`
}

// element is the shared shape. SPDX 3.0.1 serializes every element with a
// `type`, an identifier, and a CreationInfo reference; the rest varies by class
// and is carried in a map rather than a struct per class, because the profile
// fields are sparse and a struct per class would be mostly zeroes.
//
// Map key order is not a determinism hazard: encoding/json sorts map keys, so
// two renders of one inventory are byte-identical (P7). Element ORDER within
// the graph is the part that has to be arranged deliberately, and every
// producer below either preserves inventory order or sorts explicitly.
type element map[string]any

// Write emits the document.
func (wr Writer) Write(w io.Writer, inv *airom.Inventory) error {
	b := &builder{
		ns:      docNamespace + namespaceSuffix(inv) + "#",
		inv:     inv,
		agents:  map[string]string{},
		lics:    map[string]string{},
		relSeen: map[string]bool{},
	}

	// Order matters only for readability, not correctness — SPDX graphs are
	// unordered — but a document a human can skim is worth the arrangement:
	// provenance, then parties, then the things, then the claims about them.
	graph := []any{b.creationInfo(), b.toolAgent(), b.tool()}
	pkgs, ids := b.packages()
	graph = append(graph, b.agentElements()...)
	graph = append(graph, b.licenseElements()...)
	graph = append(graph, pkgs...)
	graph = append(graph, b.vulnElements()...)
	graph = append(graph, b.relationships()...)
	graph = append(graph, b.sbom(ids))

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(document{Context: contextIRI, Graph: graph})
}

type builder struct {
	ns  string
	inv *airom.Inventory

	// agents and lics are mint-on-reference registries: a package that names a
	// supplier needs an Agent element to point at, and emitting one per
	// reference would produce duplicate elements for the same organization.
	// Keyed by display name, valued by the minted spdxId.
	agents map[string]string
	lics   map[string]string

	// agentURLs and licOrder preserve first-reference order so the registries
	// can be rendered without ranging over a map, which would not be
	// deterministic (P7). Both are sorted before emission anyway; keeping the
	// slices means the sort has something stable to sort.
	agentURLs [][3]string
	licOrder  []string

	// vulns accumulates (component, finding) pairs as packages render, so the
	// security elements and their relationships stay in package order.
	vulns []vulnRef

	// relSeen deduplicates license edges: many packages share one license, and
	// the same (from, type, to) triple emitted twice is a malformed graph.
	relSeen map[string]bool

	// extra holds relationships discovered while rendering packages (licenses,
	// vulnerabilities), which have to be merged with the inventory's own edges.
	extra []element
}

// vulnRef pairs a finding with the package it was found on.
type vulnRef struct {
	pkgID string
	id    string
	// vex distinguishes a third-party advisory matched by version (a genuine
	// "this product is affected" claim) from one of AIROM's own structural
	// risk findings, which is suspicion and must not be published as a VEX
	// verdict. See relationships().
	vex     bool
	summary string
	detail  string
	source  string
	url     string
	aliases []string
	score   float64
	vector  string
	// fixedIn is the first fixed UPSTREAM release. It never becomes a "fixed"
	// assessment — the scanned tree still runs the vulnerable version, so the
	// two claims are opposites — and lives in the action statement instead,
	// exactly as in the OpenVEX writer.
	fixedIn string
}

func (b *builder) id(suffix string) string { return b.ns + suffix }

// ref strips the "airom:" scheme from a component ID and makes it an IRI.
func (b *builder) ref(id airom.ID) string {
	return b.id(strings.TrimPrefix(string(id), "airom:"))
}

// ── Document provenance (§3.1) ─────────────────────────────────────────────

// creationInfo is the one shared CreationInfo.
func (b *builder) creationInfo() element {
	return element{
		"type":         "CreationInfo",
		"@id":          creationInfoRef,
		"specVersion":  specVersion,
		"created":      b.inv.Timestamp.UTC().Format(time.RFC3339),
		"createdBy":    []string{b.id("Agent-airom")},
		"createdUsing": []string{b.id("Tool-airom")},
	}
}

// toolAgent is the party credited with creating the document. A scanner is a
// SoftwareAgent, not a Person or Organization — the distinction matters to a
// consumer deciding how much weight to give the assertions, and it is the same
// reason the VEX writer labels itself "not a supplier attestation".
func (b *builder) toolAgent() element {
	return element{
		"type":         "SoftwareAgent",
		"spdxId":       b.id("Agent-airom"),
		"name":         orDefault(b.inv.Tool.Name, "airom"),
		"creationInfo": creationInfoRef,
	}
}

// tool records the producing software (§3.1: Tool.Commit → comment).
func (b *builder) tool() element {
	e := element{
		"type":         "Tool",
		"spdxId":       b.id("Tool-airom"),
		"name":         orDefault(b.inv.Tool.Name, "airom"),
		"creationInfo": creationInfoRef,
	}
	if v := strings.TrimSpace(b.inv.Tool.Version); v != "" {
		e["software_packageVersion"] = v
	}
	if c := strings.TrimSpace(b.inv.Tool.Commit); c != "" {
		e["comment"] = "airom:tool.commit " + c
	}
	return e
}

// sbom is the SBOM element naming the root and every member (§3.1).
func (b *builder) sbom(elementIDs []string) element {
	e := element{
		"type":         "software_Sbom",
		"spdxId":       b.id("SBOM"),
		"creationInfo": creationInfoRef,
		// "build": produced by analyzing the built/described artifact. AIROM
		// scans a tree or an image rather than observing a running system, so
		// neither "runtime" nor "deployed" would be honest.
		"software_sbomType": []string{"build"},
		"element":           elementIDs,
	}
	if root := b.rootID(); root != "" {
		e["rootElement"] = []string{root}
	}
	if b.inv.Lifecycle != "" {
		// Lossy by design (§3.1): SPDX has no lifecycle-phase slot.
		addComment(e, "airom:lifecycle "+b.inv.Lifecycle)
	}
	// Said once, here, rather than on every package: SPDX 3.0.1 has nowhere to
	// put an occurrence, so the per-package airom:evidence counts are all a
	// reader gets from this format.
	addComment(e, "airom:evidence SPDX 3.0.1 has no evidence slot; each package states its "+
		"occurrence COUNT only. For the file:line evidence behind every component, take the "+
		"CycloneDX (evidence.occurrences[]) or native JSON output.")
	return e
}

// rootID is the SPDX id of the scan root. Inventory.Root is an ID reference;
// the component itself lives in Components like any other, so unlike the
// CycloneDX writer (which hoists it out into metadata.component) nothing
// special happens here beyond naming it as the SBOM's rootElement.
func (b *builder) rootID() string {
	if b.inv.Root == "" {
		return ""
	}
	return b.ref(b.inv.Root)
}

// ── Parties and licenses: mint-on-reference ────────────────────────────────

// agent returns the spdxId for a named party, minting the Agent element on
// first reference. Organization rather than Person: a package supplier is an
// org, and SPDX asks callers to be specific where they can.
func (b *builder) agent(name, url string) string {
	name = strings.TrimSpace(name)
	if id, ok := b.agents[name]; ok {
		return id
	}
	id := b.id("Agent-" + slug(name))
	b.agents[name] = id
	// The URL rides along in the element, built later from this registry.
	b.agentURLs = append(b.agentURLs, [3]string{id, name, url})
	return id
}

// agentElements renders every minted Agent, sorted by id so the graph is
// stable regardless of the order components happened to reference them.
func (b *builder) agentElements() []any {
	rows := append([][3]string(nil), b.agentURLs...)
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		e := element{
			"type":         "Organization",
			"spdxId":       r[0],
			"name":         r[1],
			"creationInfo": creationInfoRef,
		}
		if r[2] != "" {
			e["externalIdentifier"] = []element{{
				"type":                   "ExternalIdentifier",
				"externalIdentifierType": "other",
				"identifier":             r[2],
			}}
		}
		out = append(out, e)
	}
	return out
}

// license returns the spdxId for a license, minting the element on first
// reference. SPDX 3.0.1 splits listed licenses from arbitrary expressions;
// LicenseExpression accepts both, so one class covers all three shapes of
// airom.License without having to decide whether an id is on the SPDX list —
// a decision this writer has no data to make correctly.
func (b *builder) license(l airom.License) string {
	expr := licenseExpression(l)
	if expr == "" {
		return ""
	}
	if id, ok := b.lics[expr]; ok {
		return id
	}
	id := b.id("License-" + slug(expr))
	b.lics[expr] = id
	b.licOrder = append(b.licOrder, expr)
	return id
}

func (b *builder) licenseElements() []any {
	exprs := append([]string(nil), b.licOrder...)
	sort.Strings(exprs)
	out := make([]any, 0, len(exprs))
	for _, expr := range exprs {
		out = append(out, element{
			"type":                              "simplelicensing_LicenseExpression",
			"spdxId":                            b.lics[expr],
			"creationInfo":                      creationInfoRef,
			"simplelicensing_licenseExpression": expr,
		})
	}
	return out
}

// licenseExpression flattens airom.License into the one string SPDX wants.
// Exactly one field is normally set; when a name is all that is known it is
// still emitted, because a name a human can read beats no license at all and
// SPDX expressions permit LicenseRef-style free text.
func licenseExpression(l airom.License) string {
	switch {
	case strings.TrimSpace(l.Expression) != "":
		return strings.TrimSpace(l.Expression)
	case strings.TrimSpace(l.SPDXID) != "":
		return strings.TrimSpace(l.SPDXID)
	default:
		return strings.TrimSpace(l.Name)
	}
}

// ── Packages ───────────────────────────────────────────────────────────────

// packages renders every component, returning the elements and their ids.
func (b *builder) packages() ([]any, []string) {
	out := make([]any, 0, len(b.inv.Components))
	ids := make([]string, 0, len(b.inv.Components))

	for i := range b.inv.Components {
		c := &b.inv.Components[i]
		out = append(out, b.pkg(c))
		ids = append(ids, b.ref(c.ID))
	}
	sort.Strings(ids)
	return out, ids
}

// classOf maps a kind to its SPDX element class and primary purpose (§4).
func classOf(k airom.ComponentKind) (class, purpose string) {
	switch k {
	case airom.KindHostedLLM, airom.KindLocalModelFile, airom.KindEmbeddingModel:
		return "ai_AIPackage", "model"
	case airom.KindDataset:
		return "dataset_DatasetPackage", "data"
	case airom.KindFramework:
		return "software_Package", "framework"
	case airom.KindLibrary:
		return "software_Package", "library"
	case airom.KindPrompt:
		return "software_Package", "data"
	case airom.KindAIConfig:
		return "software_Package", "configuration"
	default:
		// vector-db, infra, service, rag-pipeline, application (§4 coarsening).
		return "software_Package", "application"
	}
}

// pkg renders one component.
func (b *builder) pkg(c *airom.Component) element {
	class, purpose := classOf(c.Kind)
	e := element{
		"type":                    class,
		"spdxId":                  b.ref(c.ID),
		"name":                    c.Name,
		"creationInfo":            creationInfoRef,
		"software_primaryPurpose": purpose,
	}

	// ai_AIPackage and dataset_DatasetPackage carry required fields that a
	// software_Package does not. Where AIROM does not know the answer, §6.4
	// says to write NOASSERTION rather than omit — the field is required, so
	// omission would be invalid and silence would be indistinguishable from a
	// real value.
	required := class != "software_Package"

	b.identity(e, c, required)
	b.provenance(e, c, required)

	switch class {
	case "ai_AIPackage":
		b.aiFields(e, c)
	case "dataset_DatasetPackage":
		b.datasetFields(e, c)
	}
	b.overflow(e, c)
	b.declaredLicenses(c)
	b.findings(c)

	// The exact kind always survives, the way it does in CycloneDX: five kinds
	// coarsen to "application" and the reader must be able to recover which.
	addComment(e, "airom:kind "+string(c.Kind))
	return e
}

// identity fills name/version/purl/hashes.
func (b *builder) identity(e element, c *airom.Component, required bool) {
	switch v, ok := c.Version.Value(); {
	case ok && v != "":
		e["software_packageVersion"] = v
	case c.VersionConstraint != "":
		// A declared range is not a version. Writing ">=1.0,<2" into
		// software_packageVersion would hand every downstream matcher a string
		// it will treat as a release, which is precisely the confusion
		// VersionConstraint exists to prevent — so the field stays
		// unasserted and the range is stated where it cannot be mistaken for
		// one.
		if required {
			e["software_packageVersion"] = noAssertion
		}
		addComment(e, "airom:versionConstraint "+c.VersionConstraint)
	case required:
		e["software_packageVersion"] = noAssertion
	}

	if c.Group != "" {
		// Lossy (§3.2): SPDX 3.0.1 packages have no group/namespace slot.
		addComment(e, "airom:group "+c.Group)
	}
	if c.PURL != "" {
		e["externalIdentifier"] = []element{{
			"type":                   "ExternalIdentifier",
			"externalIdentifierType": "packageUrl",
			"identifier":             c.PURL,
		}}
	}
	if h := hashes(c.Hashes); len(h) > 0 {
		e["verifiedUsing"] = h
	}
}

// provenance fills the supplier, download location, and time fields.
func (b *builder) provenance(e element, c *airom.Component, required bool) {
	// suppliedBy takes an ELEMENT reference, so an unknown supplier is the
	// NoAssertionElement individual rather than the string (§6.4).
	switch prov, hasProv := c.Provider.Value(); {
	case c.Supplier != nil && c.Supplier.Name != "":
		e["suppliedBy"] = b.agent(c.Supplier.Name, c.Supplier.URL)
	case hasProv && prov != "":
		e["suppliedBy"] = b.agent(prov, "")
	case required:
		e["suppliedBy"] = noAssertionElement
	}

	dl, hasDL := c.DownloadLocation.Value()
	if (!hasDL || dl == "") && c.Data != nil {
		// §3.5: a dataset's contents URL is its download location.
		dl, hasDL = c.Data.URL.Value()
	}
	switch {
	case hasDL && dl != "":
		e["software_downloadLocation"] = dl
	case required:
		e["software_downloadLocation"] = noAssertion
	}

	if t, ok := c.ReleaseTime.Value(); ok {
		e["releaseTime"] = t.UTC().Format(time.RFC3339)
	} else if required {
		// A DateTime field cannot carry the string NOASSERTION, so the
		// no-assertion is expressed by omission plus an explicit note. This is
		// the one place §6.4's scalar rule cannot apply literally.
		addComment(e, "airom:releaseTime NOASSERTION")
	}

	if c.SourceInfo != "" {
		addComment(e, c.SourceInfo)
	}
	if c.TestOnly {
		// CycloneDX has `scope: excluded` for this; SPDX has nothing. Saying
		// so matters more here than elsewhere, because a consumer who reads a
		// fixture as a production dependency draws exactly the wrong
		// conclusion from an otherwise correct document.
		addComment(e, "airom:testOnly true — every occurrence is test scaffolding")
	}
}

// aiFields fills the AI-profile slots for a model component (§3.3, §3.4).
func (b *builder) aiFields(e element, c *airom.Component) {
	if c.EOL != nil && c.EOL.Shutdown != nil {
		// validUntilTime is Core's "do not use after" instant, which is
		// precisely what a provider shutdown date is. The catalog records a
		// calendar day, so it is anchored at the start of that day in UTC
		// rather than given an invented time of day.
		e["validUntilTime"] = c.EOL.Shutdown.String() + "T00:00:00Z"
		addComment(e, "airom:eol "+eolNote(c.EOL))
	}

	m := c.Model
	if m == nil {
		return
	}
	if v, ok := m.Task.Value(); ok && v != "" {
		// Lossy (§3.3): task is not domain, but ai_domain is the nearest slot
		// the profile offers and dropping the only functional description of a
		// model would be worse than approximating it.
		e["ai_domain"] = []string{v}
	}
	var typeOfModel []string
	if v, ok := m.Architecture.Value(); ok && v != "" {
		typeOfModel = append(typeOfModel, v)
	}
	if len(typeOfModel) > 0 {
		e["ai_typeOfModel"] = typeOfModel
	}

	// No SPDX home (§3.3 marks these lossy) — kept readable rather than lost.
	if v, ok := m.ParamCount.Value(); ok {
		addComment(e, "airom:model.paramCount "+strconv.FormatInt(v, 10))
	}
	if v, ok := m.ContextLength.Value(); ok {
		addComment(e, "airom:model.contextLength "+strconv.FormatInt(v, 10))
	}
	if v, ok := m.Quantization.Value(); ok && v != "" {
		addComment(e, "airom:model.quantization "+v)
	}
	if v, ok := m.Format.Value(); ok && v != "" {
		addComment(e, "airom:model.format "+v)
	}
	if v, ok := m.BaseModel.Value(); ok && v != "" {
		// Also a derived-from edge when the base component is in the graph
		// (§3.10); the property survives either way, since the base model is
		// frequently a name AIROM never saw as a component.
		addComment(e, "airom:model.baseModel "+v)
	}
	// GenerationParams are inference-time settings; SPDX ai_hyperparameter is
	// training-time config, and putting one in the other's slot would publish
	// a false claim about how the model was built (§3.3).
	for _, p := range m.GenerationParams {
		addComment(e, "airom:param."+p.Name+" "+p.Value)
	}
	if m.Card != nil {
		b.cardFields(e, m.Card)
	}
}

// cardFields projects the model card (§3.4).
func (b *builder) cardFields(e element, card *airom.ModelCard) {
	if len(card.Metrics) > 0 {
		entries := make([]element, 0, len(card.Metrics))
		for _, m := range card.Metrics {
			key := m.Type
			if m.Slice != "" {
				key += " (" + m.Slice + ")"
			}
			entries = append(entries, element{
				"type": "DictionaryEntry", "key": key, "value": m.Value,
			})
		}
		e["ai_metric"] = entries
	}
	if card.Considerations != nil {
		app := append(append([]string(nil), card.Considerations.Users...), card.Considerations.UseCases...)
		if len(app) > 0 {
			// Lossy (§3.4): ai_informationAboutApplication is 0..1, so two
			// lists become one string.
			e["ai_informationAboutApplication"] = strings.Join(app, "; ")
		}
		if lim := card.Considerations.TechnicalLimitations; len(lim) > 0 {
			e["ai_limitation"] = strings.Join(lim, "; ")
		}
	}
	if len(card.Energy) > 0 {
		b.energy(e, card.Energy)
	}
}

// energy projects modelCard energy into ai_energyConsumption (§3.4). SPDX
// buckets consumption by activity into three fixed slots; anything else has no
// home, so it is noted rather than dropped.
func (b *builder) energy(e element, rows []airom.EnergyConsumption) {
	buckets := map[string][]element{}
	for _, r := range rows {
		slot := ""
		switch strings.ToLower(strings.TrimSpace(r.Activity)) {
		case "training":
			slot = "ai_trainingEnergyConsumption"
		case "finetuning", "fine-tuning", "fine tuning":
			slot = "ai_finetuningEnergyConsumption"
		case "inference":
			slot = "ai_inferenceEnergyConsumption"
		default:
			addComment(e, fmt.Sprintf("airom:model.energy.%s %g kWh", slug(r.Activity), r.KWh))
			continue
		}
		buckets[slot] = append(buckets[slot], element{
			"type":              "ai_EnergyConsumptionDescription",
			"ai_energyQuantity": r.KWh,
			"ai_energyUnit":     "kilowattHour",
		})
	}
	if len(buckets) == 0 {
		return
	}
	consumption := element{"type": "ai_EnergyConsumption"}
	for slot, rows := range buckets {
		consumption[slot] = rows
	}
	e["ai_energyConsumption"] = consumption
}

// datasetFields fills the Dataset-profile slots (§3.5).
func (b *builder) datasetFields(e element, c *airom.Component) {
	// dataset_datasetType is required 1..* and is a controlled vocabulary, so
	// an unknown type is the enum member noAssertion — not an omission and not
	// a free string.
	types := []string{noAssertionDatasetType}
	if c.Data != nil {
		if f, ok := c.Data.Format.Value(); ok && f != "" {
			if t := datasetType(f); t != "" {
				types = []string{t}
			}
			addComment(e, "airom:dataset.format "+f)
		}
		if n, ok := c.Data.SizeBytes.Value(); ok {
			e["dataset_datasetSize"] = n
		}
	}
	e["dataset_datasetType"] = types

	// originatedBy is required and takes an element reference. AIROM does not
	// model dataset governance, so this is always a no-assertion rather than a
	// guess that the supplier also originated the data — for a dataset those
	// are routinely different parties, and conflating them would be a claim
	// about provenance that nobody made.
	e["originatedBy"] = []string{noAssertionElement}

	// builtTime is required and is a DateTime, so as with releaseTime the
	// no-assertion can only be a note (§6.4).
	addComment(e, "airom:builtTime NOASSERTION")
}

// datasetType maps a serialization format onto the SPDX dataset-type
// vocabulary. Only the mappings that are actually sound are made: a CSV or a
// Parquet file is structured data by construction, whereas "hf-dataset" says
// where the data came from and nothing at all about what is in it.
func datasetType(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "csv", "tsv", "jsonl", "json", "parquet", "arrow":
		return "structured"
	case "prompt-template", "txt", "text":
		return "text"
	default:
		return ""
	}
}

// overflow carries the fields with no profile home at all.
func (b *builder) overflow(e element, c *airom.Component) {
	if c.Infra != nil {
		if v, ok := c.Infra.Endpoint.Value(); ok && v != "" {
			addComment(e, "airom:service.endpoint "+v)
		}
		if v, ok := c.Infra.Region.Value(); ok && v != "" {
			addComment(e, "airom:infra.region "+v)
		}
		if v, ok := c.Infra.Deployment.Value(); ok && v != "" {
			addComment(e, "airom:infra.deployment "+v)
		}
	}
	if c.Package != nil && c.Package.Ecosystem != "" {
		// Already inside the purl when there is one; stated anyway for the
		// components that have no purl by design (D9).
		addComment(e, "airom:package.ecosystem "+c.Package.Ecosystem)
	}
	for _, p := range c.Props {
		addComment(e, p.Name+" "+p.Value)
	}
	// Confidence and Evidence are the documented SPDX losses (§3.2). The
	// assembled confidence is one number and costs one comment, so it is kept;
	// the occurrence list is not, so its COUNT is stated — a reader who sees
	// "3 occurrences" and no occurrences knows to go get the CycloneDX, which
	// beats a silently evidence-free document. The prose explaining that lives
	// once on the SBOM element rather than on every package.
	//
	// Confidence 0 is the assembler's value for a component nothing scored —
	// the scan root. Writing "confidence 0" would read as "we looked and found
	// no support for this", a different and false claim.
	if c.Confidence > 0 {
		addComment(e, fmt.Sprintf("airom:confidence %.3g", float64(c.Confidence)))
	}
	if n := len(c.Evidence.Occurrences); n > 0 {
		addComment(e, fmt.Sprintf("airom:evidence %d occurrence(s)", n))
	}
}

// findings queues this component's security findings for the security-profile
// elements built later. Nothing is written to the package itself: in SPDX a
// vulnerability is a first-class element joined by a relationship, not a field.
func (b *builder) findings(c *airom.Component) {
	pkgID := b.ref(c.ID)
	for _, v := range c.Vulnerabilities {
		b.vulns = append(b.vulns, vulnRef{
			pkgID: pkgID, id: v.ID, vex: true,
			summary: v.Summary, source: v.Source, url: v.URL,
			aliases: v.Aliases, score: v.Score, vector: v.Vector,
			fixedIn: v.Fixed,
		})
	}
	for _, r := range c.Risks {
		meta := airom.RiskByID(r.ID)
		detail := meta.Description
		if len(r.Detail) > 0 {
			// The catalog says what the risk class means; ArtifactRisk.Detail
			// carries the specifics that make it actionable — the actual
			// symbols found. Both, or a reader gets a lecture with no lead.
			detail += " Found: " + strings.Join(r.Detail, ", ") + "."
		}
		b.vulns = append(b.vulns, vulnRef{
			pkgID: pkgID, id: string(r.ID), vex: false,
			summary: meta.Title, detail: detail,
			source: "airom (" + string(r.Severity) + " severity)",
		})
	}
}

// vulnElements renders one security_Vulnerability per finding, in the order
// the packages were rendered.
func (b *builder) vulnElements() []any {
	out := make([]any, 0, len(b.vulns))
	for i, v := range b.vulns {
		e := element{
			"type":         "security_Vulnerability",
			"spdxId":       b.id(fmt.Sprintf("Vulnerability-%d-%s", i, slug(v.id))),
			"name":         v.id,
			"creationInfo": creationInfoRef,
		}
		if v.summary != "" {
			e["summary"] = v.summary
		}
		if v.detail != "" {
			e["description"] = v.detail
		}
		ids := make([]element, 0, len(v.aliases)+1)
		for _, a := range v.aliases {
			ids = append(ids, element{
				"type": "ExternalIdentifier", "externalIdentifierType": "securityOther", "identifier": a,
			})
		}
		if len(ids) > 0 {
			e["externalIdentifier"] = ids
		}
		if v.url != "" {
			e["externalRef"] = []element{{
				"type": "ExternalRef", "externalRefType": "securityAdvisory", "locator": []string{v.url},
			}}
		}
		if v.vector != "" {
			addComment(e, "airom:cvss "+v.vector+" ("+strconv.FormatFloat(v.score, 'f', -1, 64)+")")
		}
		if v.source != "" {
			addComment(e, "airom:source "+v.source)
		}
		out = append(out, e)
	}
	return out
}

// ── Relationships ──────────────────────────────────────────────────────────

// spdxRelType maps AIROM's relationship vocabulary (§3.10). Where SPDX has no
// equivalent the edge becomes `other` plus a comment naming the real type, so
// nothing is silently dropped.
func spdxRelType(t airom.RelType) (string, bool) {
	switch t {
	case airom.RelDependsOn:
		return "dependsOn", true
	case airom.RelTrainedOn:
		return "trainedOn", true
	case airom.RelContains:
		return "contains", true
	case airom.RelPromptedBy:
		return "hasInput", true
	case airom.RelDerivedFrom:
		return "descendantOf", true
	case airom.RelConfigures:
		return "configures", true
	default:
		// uses, served-by, queries, embeds-with.
		return "other", false
	}
}

// relationships renders the inventory's edges plus the license and security
// edges minted while packages rendered.
func (b *builder) relationships() []any {
	out := make([]any, 0, len(b.inv.Relationships)+len(b.extra))
	for i, r := range b.inv.Relationships {
		typ, exact := spdxRelType(r.Type)
		e := element{
			"type":             "Relationship",
			"spdxId":           b.id(fmt.Sprintf("Relationship-%d", i)),
			"creationInfo":     creationInfoRef,
			"from":             b.ref(r.From),
			"to":               []string{b.ref(r.To)},
			"relationshipType": typ,
		}
		if !exact {
			addComment(e, "airom:rel."+string(r.Type))
		}
		if r.Confidence > 0 {
			// Lossy in the table (§3.10); a comment costs nothing and an edge
			// asserted at 0.6 is a different statement from one at 0.99.
			addComment(e, fmt.Sprintf("airom:rel.confidence %.3g", float64(r.Confidence)))
		}
		out = append(out, e)
	}
	for _, e := range b.extra {
		out = append(out, e)
	}
	out = append(out, b.vulnRels()...)
	return out
}

// declaredLicenses mints the license elements and their edges. It runs while
// packages render, not from relationships(), because licenseElements() is
// emitted before relationships() are built — minting there would produce edges
// pointing at license elements the document never declared.
func (b *builder) declaredLicenses(c *airom.Component) {
	for _, l := range c.Licenses {
		licID := b.license(l)
		if licID == "" {
			continue
		}
		key := string(c.ID) + "|" + licID
		if b.relSeen[key] {
			continue
		}
		b.relSeen[key] = true
		b.extra = append(b.extra, element{
			"type":             "Relationship",
			"spdxId":           b.id(fmt.Sprintf("LicenseRelationship-%d", len(b.extra))),
			"creationInfo":     creationInfoRef,
			"from":             b.ref(c.ID),
			"to":               []string{licID},
			"relationshipType": "hasDeclaredLicense",
		})
	}
}

// vulnRels joins findings to the packages they were found on.
//
// The distinction between the two branches is the whole reason this writer has
// a `vex` flag. A CVE from the overlay was matched because the installed
// version falls inside an advisory's affected range — that is a genuine
// "affected" claim and it is the same one the OpenVEX writer publishes. An
// ArtifactRisk is AIROM's own structural finding: "this checkpoint contains a
// deserialization surface" is suspicion with evidence, explicitly not a
// verdict (see airom.ArtifactRisk), so it gets a plain association and no VEX
// assessment. Publishing it as one would turn a lead into an accusation.
//
// Neither branch can ever produce not_affected or fixed: AIROM does no
// reachability analysis, so it has no grounds for an all-clear — the one
// output that would make a consumer stop looking.
func (b *builder) vulnRels() []any {
	out := make([]any, 0, len(b.vulns))
	for i, v := range b.vulns {
		vulnID := b.id(fmt.Sprintf("Vulnerability-%d-%s", i, slug(v.id)))
		e := element{
			"spdxId":           b.id(fmt.Sprintf("VulnRelationship-%d", i)),
			"creationInfo":     creationInfoRef,
			"relationshipType": "hasAssociatedVulnerability",
		}
		if v.vex {
			// A VulnAssessmentRelationship constrains `from` to be the
			// Vulnerability and `to` to be the affected products — the
			// opposite of Core's own direction for this relationship type,
			// which the security profile deliberately inverts.
			e["from"], e["to"] = vulnID, []string{v.pkgID}
			e["type"] = "security_VexAffectedVulnAssessmentRelationship"
			if v.fixedIn != "" {
				e["security_actionStatement"] = "Upgrade to " + v.fixedIn + " or later."
			} else {
				e["security_actionStatement"] = "No fixed version is named by the advisory; consult " + orDefault(v.url, v.source) + "."
			}
		} else {
			// A plain Relationship follows Core's direction: the from Element
			// is associated with the to Vulnerability.
			e["from"], e["to"] = v.pkgID, []string{vulnID}
			e["type"] = "Relationship"
			addComment(e, "airom:risk — a statically-detected structural finding, not a third-party advisory and not a VEX assessment")
		}
		out = append(out, e)
	}
	return out
}

// ── Helpers ────────────────────────────────────────────────────────────────

// hashes renders SHA-256 digests. XXH3 is cache-internal and never emitted.
func hashes(hs []airom.Hash) []element {
	var out []element
	for _, h := range hs {
		if !strings.EqualFold(h.Alg, "SHA-256") {
			continue
		}
		out = append(out, element{
			"type": "Hash", "algorithm": "sha256", "hashValue": strings.ToLower(h.Hex),
		})
	}
	return out
}

// eolNote summarizes a lifecycle record for the element comment.
func eolNote(l *airom.Lifecycle) string {
	parts := []string{string(l.State)}
	if l.Shutdown != nil {
		parts = append(parts, "shutdown "+l.Shutdown.String())
	}
	if l.Replacement != "" {
		parts = append(parts, "replacement "+l.Replacement)
	}
	if l.SourceURL != "" {
		parts = append(parts, l.SourceURL)
	}
	return strings.Join(parts, "; ")
}

// namespaceSuffix derives the document namespace segment from the scan serial,
// which is already unique per scan.
func namespaceSuffix(inv *airom.Inventory) string {
	if s := strings.TrimPrefix(inv.Serial, "urn:uuid:"); s != "" {
		return s
	}
	return inv.Timestamp.UTC().Format("20060102T150405Z")
}

// addComment joins comments rather than overwriting: several sources feed one
// field, and the last writer silently winning would drop the others.
func addComment(e element, add string) {
	if cur, ok := e["comment"].(string); ok && cur != "" {
		e["comment"] = cur + "; " + add
		return
	}
	e["comment"] = add
}

// slug makes an identifier-safe fragment from a display name.
func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func orDefault(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
