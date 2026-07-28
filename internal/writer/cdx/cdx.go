package cdx

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

// format is the registered name of this writer.
const format = "cyclonedx"

func init() {
	writer.Register(format, func(o writer.Options) writer.Writer { return New(o) })
}

// cdxWriter projects an *airom.Inventory to a CycloneDX 1.6 (or 1.7) ML-BOM
// per docs/mapping.md. It is a pure projection (invariant P5): no I/O
// decisions, no re-derivation.
type cdxWriter struct {
	opts writer.Options
}

// New returns a CycloneDX writer for the given options.
func New(o writer.Options) writer.Writer { return &cdxWriter{opts: o} }

// Format returns the writer's registered format name.
func (*cdxWriter) Format() string { return format }

// Write renders inv as a CycloneDX JSON document to out.
//
// The document is version-parameterized by Options.CDXVersion ("1.6" default,
// "1.7"): the modelCard shape is identical across both, so only the declared
// SpecVersion and $schema differ (the 1.6→1.7 delta is four externalReference
// types AIROM never emits).
//
// We stamp SpecVersion/$schema directly and call enc.Encode rather than
// enc.EncodeVersion. EncodeVersion deep-copies the BOM through encoding/gob,
// which rewrites a non-nil empty slice as a nil pointer; that turns the
// schema-required-but-provider-less energyConsumptions[].energyProviders array
// into JSON null (schema-invalid). enc.Encode preserves the empty [] array.
// Every field AIROM emits is a ≤1.6 feature, so no downgrade conversion is
// needed and the output is byte-equivalent to EncodeVersion modulo that fix.
func (w *cdxWriter) Write(out io.Writer, inv *airom.Inventory) error {
	sv := cyclonedx.SpecVersion1_6
	if w.opts.CDXVersion == "1.7" {
		sv = cyclonedx.SpecVersion1_7
	}

	bom := newBuilder(inv).build()
	bom.SpecVersion = sv
	bom.JSONSchema = schemaURL(sv)

	enc := cyclonedx.NewBOMEncoder(out, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.Encode(bom); err != nil {
		return fmt.Errorf("cyclonedx encode: %w", err)
	}
	return nil
}

func schemaURL(v cyclonedx.SpecVersion) string {
	if v == cyclonedx.SpecVersion1_7 {
		return "http://cyclonedx.org/schema/bom-1.7.schema.json"
	}
	return "http://cyclonedx.org/schema/bom-1.6.schema.json"
}

// ── Builder ─────────────────────────────────────────────────────────────────

// builder holds the inventory plus the relationship indexes derived once
// (§3.10 routing): trained-on edges become modelCard datasets, depends-on
// edges become dependencies[], everything else becomes airom:rel.* props.
type builder struct {
	inv *airom.Inventory

	// trainedOn maps a model component ID → the dataset bom-refs it trained on
	// (modelCard.modelParameters.datasets[].ref).
	trainedOn map[airom.ID][]string
	// relProps maps a From component ID → its non-dependency, non-trained-on
	// edges (airom:rel.<type> = "<to>@<confidence>").
	relProps map[airom.ID][]airom.Relationship
}

func newBuilder(inv *airom.Inventory) *builder {
	b := &builder{
		inv:       inv,
		trainedOn: map[airom.ID][]string{},
		relProps:  map[airom.ID][]airom.Relationship{},
	}
	for _, r := range inv.Relationships {
		switch r.Type {
		case airom.RelDependsOn:
			// dependencies[] — built separately in buildDependencies.
		case airom.RelTrainedOn:
			b.trainedOn[r.From] = append(b.trainedOn[r.From], string(r.To))
		default:
			b.relProps[r.From] = append(b.relProps[r.From], r)
		}
	}
	return b
}

func (b *builder) build() *cyclonedx.BOM {
	inv := b.inv
	bom := cyclonedx.NewBOM()
	// Serial is already a full "urn:uuid:<uuid>" URN (assembler's newSerial);
	// emit it verbatim. Tolerate a bare UUID for hand-built inventories.
	bom.SerialNumber = inv.Serial
	if inv.Serial != "" && !strings.HasPrefix(inv.Serial, "urn:uuid:") {
		bom.SerialNumber = "urn:uuid:" + inv.Serial
	}
	bom.Metadata = b.metadata()

	// Components arrive sorted by ID (deterministic, P7); preserve that order.
	// The Root is emitted as metadata.component and never duplicated here.
	comps := make([]cyclonedx.Component, 0, len(inv.Components))
	for i := range inv.Components {
		c := &inv.Components[i]
		if c.ID == inv.Root {
			rc := b.component(c)
			bom.Metadata.Component = &rc
			continue
		}
		comps = append(comps, b.component(c))
	}
	if len(comps) > 0 {
		bom.Components = &comps
	}

	if deps := buildDependencies(inv); len(deps) > 0 {
		bom.Dependencies = &deps
	}
	if vulns := buildVulnerabilities(inv); len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}
	if len(inv.Compliance) > 0 {
		bom.Definitions = buildDefinitions(inv)
		bom.Declarations = buildDeclarations(inv)
	}
	return bom
}

// ── metadata (§3.1) ─────────────────────────────────────────────────────────

func (b *builder) metadata() *cyclonedx.Metadata {
	inv := b.inv
	md := &cyclonedx.Metadata{
		Timestamp: inv.Timestamp.UTC().Format(time.RFC3339),
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{{
				Type:    cyclonedx.ComponentTypeApplication,
				Name:    inv.Tool.Name,
				Version: inv.Tool.Version,
			}},
		},
	}
	if inv.Lifecycle != "" {
		md.Lifecycles = &[]cyclonedx.Lifecycle{{Phase: cyclonedx.LifecyclePhase(inv.Lifecycle)}}
	}

	var props propList
	if inv.Tool.Commit != "" {
		props.add("airom:tool.commit", inv.Tool.Commit)
	}
	if inv.Tool.RulesVersion != "" {
		props.add("airom:rules.version", inv.Tool.RulesVersion)
	}
	if inv.Tool.RulesHash != "" {
		props.add("airom:rules.hash", inv.Tool.RulesHash)
	}
	if inv.Tool.EOLCatalog != "" {
		props.add("airom:eol.catalog", inv.Tool.EOLCatalog)
	}
	if inv.Source.Kind != "" {
		props.add("airom:source.type", inv.Source.Kind)
	}
	if inv.Source.Target != "" {
		props.add("airom:source.target", inv.Source.Target)
	}
	if inv.Source.ImageDigest != "" {
		props.add("airom:source.digest", inv.Source.ImageDigest)
	}
	if g := inv.Source.Git; g != nil {
		if g.Remote != "" {
			props.add("airom:source.git.remote", g.Remote)
		}
		if g.Commit != "" {
			props.add("airom:source.git.commit", g.Commit)
		}
		props.add("airom:source.git.dirty", strconv.FormatBool(g.Dirty))
	}
	if k := inv.Source.K8s; k != nil && k.Context != "" {
		props.add("airom:source.k8s.context", k.Context)
	}
	// Honesty over silence (P6): the unknown count always surfaces.
	props.add("airom:unknowns", strconv.Itoa(len(inv.Unknowns)))

	md.Properties = props.sorted()
	return md
}

// ── component (§3.2) ────────────────────────────────────────────────────────

func (b *builder) component(c *airom.Component) cyclonedx.Component {
	cc := cyclonedx.Component{
		BOMRef: string(c.ID),
		Type:   cdxType(c.Kind),
		Name:   c.Name,
		Group:  c.Group,
	}
	if c.TestOnly {
		// CycloneDX's own answer for "present in the source tree but not in the
		// deployed thing". Scoped, never dropped: a consumer asking "does this
		// project touch a retired model anywhere?" still gets a truthful yes,
		// while one building a production inventory can filter on scope.
		cc.Scope = cyclonedx.ScopeExcluded
	}
	if v, ok := c.Version.Value(); ok {
		cc.Version = v
	}
	if c.PURL != "" {
		cc.PackageURL = c.PURL
	}
	if c.SourceInfo != "" {
		cc.Description = c.SourceInfo
	}
	cc.Licenses = licenses(c.Licenses)
	cc.Supplier = supplier(c.Supplier)
	cc.Hashes = hashes(c.Hashes)
	cc.ExternalReferences = externalRefs(c)
	cc.Data = dataFacet(c)
	cc.ModelCard = b.modelCard(c)
	cc.Evidence = evidence(c)
	cc.Properties = b.properties(c)
	return cc
}

// cdxType maps a ComponentKind to the coarser CDX component.type (§4). The
// exact kind always survives in the airom:kind property.
func cdxType(k airom.ComponentKind) cyclonedx.ComponentType {
	switch k {
	case airom.KindHostedLLM, airom.KindLocalModelFile, airom.KindEmbeddingModel:
		return cyclonedx.ComponentTypeMachineLearningModel
	case airom.KindFramework:
		return cyclonedx.ComponentTypeFramework
	case airom.KindLibrary:
		return cyclonedx.ComponentTypeLibrary
	case airom.KindPrompt, airom.KindDataset, airom.KindAIConfig:
		return cyclonedx.ComponentTypeData
	default: // vector-db, infra, service, rag-pipeline, application
		return cyclonedx.ComponentTypeApplication
	}
}

// dataType maps a data-kind to CDX data[].type (§4).
func dataType(k airom.ComponentKind) cyclonedx.ComponentDataType {
	switch k {
	case airom.KindDataset:
		return cyclonedx.ComponentDataTypeDataset
	case airom.KindAIConfig:
		return cyclonedx.ComponentDataTypeConfiguration
	default: // prompt
		return cyclonedx.ComponentDataTypeOther
	}
}

func licenses(ls []airom.License) *cyclonedx.Licenses {
	if len(ls) == 0 {
		return nil
	}
	out := make(cyclonedx.Licenses, 0, len(ls))
	for _, l := range ls {
		switch {
		case l.Expression != "":
			out = append(out, cyclonedx.LicenseChoice{Expression: l.Expression})
		case l.SPDXID != "":
			out = append(out, cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: l.SPDXID}})
		case l.Name != "":
			out = append(out, cyclonedx.LicenseChoice{License: &cyclonedx.License{Name: l.Name}})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

func supplier(p *airom.Party) *cyclonedx.OrganizationalEntity {
	if p == nil {
		return nil
	}
	oe := &cyclonedx.OrganizationalEntity{Name: p.Name}
	if p.URL != "" {
		oe.URL = &[]string{p.URL}
	}
	return oe
}

// hashes emits SHA-256 digests only (§3.2): XXH3 is cache-internal and absent
// from the CDX alg enum.
func hashes(hs []airom.Hash) *[]cyclonedx.Hash {
	var out []cyclonedx.Hash
	for _, h := range hs {
		if strings.EqualFold(h.Alg, "SHA-256") || strings.EqualFold(h.Alg, "sha256") {
			out = append(out, cyclonedx.Hash{Algorithm: cyclonedx.HashAlgoSHA256, Value: h.Hex})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

// externalRefs carries downloadLocation (distribution) and attestations (§3.2).
func externalRefs(c *airom.Component) *[]cyclonedx.ExternalReference {
	var out []cyclonedx.ExternalReference
	if dl, ok := c.DownloadLocation.Value(); ok && dl != "" {
		out = append(out, cyclonedx.ExternalReference{Type: cyclonedx.ERTypeDistribution, URL: dl})
	}
	for _, a := range c.Attestations {
		if a.URI != "" { // url is schema-required on an externalReference
			out = append(out, cyclonedx.ExternalReference{Type: cyclonedx.ERTypeAttestation, URL: a.URI})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

// dataFacet emits the data[] facet for data-typed components (§3.5). data[].type
// is driven by the exact kind; the contents URL is the one natively-homed field.
func dataFacet(c *airom.Component) *[]cyclonedx.ComponentData {
	if cdxType(c.Kind) != cyclonedx.ComponentTypeData {
		return nil
	}
	cd := cyclonedx.ComponentData{Type: dataType(c.Kind), Name: c.Name}
	if c.Data != nil {
		if u, ok := c.Data.URL.Value(); ok && u != "" {
			cd.Contents = &cyclonedx.ComponentDataContents{URL: u}
		}
	}
	return &[]cyclonedx.ComponentData{cd}
}

// ── modelCard (§3.3 / §3.4) ─────────────────────────────────────────────────

func (b *builder) modelCard(c *airom.Component) *cyclonedx.MLModelCard {
	if cdxType(c.Kind) != cyclonedx.ComponentTypeMachineLearningModel {
		return nil
	}
	var task, arch string
	var haveTask, haveArch, haveCard bool
	if c.Model != nil {
		task, haveTask = c.Model.Task.Value()
		arch, haveArch = c.Model.Architecture.Value()
		haveCard = c.Model.Card != nil
	}
	trained := b.trainedOn[c.ID]

	// Emission rule (§3.3): ML type AND at least one of these.
	if !haveTask && !haveArch && !haveCard && len(trained) == 0 {
		return nil
	}

	mc := &cyclonedx.MLModelCard{}

	mp := &cyclonedx.MLModelParameters{}
	setMP := false
	if haveTask {
		mp.Task = task
		setMP = true
	}
	if haveArch {
		mp.ModelArchitecture = arch
		setMP = true
	}
	if len(trained) > 0 {
		ds := make([]cyclonedx.MLDatasetChoice, 0, len(trained))
		for _, ref := range trained {
			ds = append(ds, cyclonedx.MLDatasetChoice{Ref: ref})
		}
		mp.Datasets = &ds
		setMP = true
	}
	if setMP {
		mc.ModelParameters = mp
	}

	if haveCard {
		applyCard(mc, c.Model.Card)
	}
	return mc
}

// applyCard maps the airom.ModelCard onto native CDX modelCard fields (§3.4),
// best-effort against the current struct (metrics / considerations / energy).
func applyCard(mc *cyclonedx.MLModelCard, card *airom.ModelCard) {
	if len(card.Metrics) > 0 {
		pms := make([]cyclonedx.MLPerformanceMetric, 0, len(card.Metrics))
		for _, m := range card.Metrics {
			// Values are strings per schema — never numbers.
			pms = append(pms, cyclonedx.MLPerformanceMetric{Type: m.Type, Value: m.Value, Slice: m.Slice})
		}
		mc.QuantitativeAnalysis = &cyclonedx.MLQuantitativeAnalysis{PerformanceMetrics: &pms}
	}

	var cons cyclonedx.MLModelCardConsiderations
	haveCons := false
	if card.Considerations != nil {
		if v := card.Considerations.Users; len(v) > 0 {
			cp := append([]string(nil), v...)
			cons.Users = &cp
			haveCons = true
		}
		if v := card.Considerations.UseCases; len(v) > 0 {
			cp := append([]string(nil), v...)
			cons.UseCases = &cp
			haveCons = true
		}
		if v := card.Considerations.TechnicalLimitations; len(v) > 0 {
			cp := append([]string(nil), v...)
			cons.TechnicalLimitations = &cp
			haveCons = true
		}
	}
	if len(card.Energy) > 0 {
		ecs := make([]cyclonedx.MLModelEnergyConsumption, 0, len(card.Energy))
		for _, e := range card.Energy {
			ecs = append(ecs, cyclonedx.MLModelEnergyConsumption{
				Activity: energyActivity(e.Activity),
				// Schema requires energyProviders; AIROM has no provider data,
				// so an empty array satisfies the type without inventing any.
				EnergyProviders: &[]cyclonedx.MLModelEnergyProvider{},
				ActivityEnergyCost: cyclonedx.MLModelEnergyMeasure{
					Value: float32(e.KWh),
					Unit:  cyclonedx.MLModelEnergyUnitKWH,
				},
			})
		}
		cons.EnvironmentalConsiderations = &cyclonedx.MLModelCardEnvironmentalConsiderations{
			EnergyConsumptions: &ecs,
		}
		haveCons = true
	}
	if haveCons {
		mc.Considerations = &cons
	}
}

// energyActivity constrains a free-text activity to the CDX enum; anything
// outside it degrades to "other" (§3.4).
func energyActivity(s string) cyclonedx.MLModelEnergyConsumptionActivity {
	switch cyclonedx.MLModelEnergyConsumptionActivity(s) {
	case cyclonedx.MLModelEnergyConsumptionActivityDesign,
		cyclonedx.MLModelEnergyConsumptionActivityDataCollection,
		cyclonedx.MLModelEnergyConsumptionActivityDataPreparation,
		cyclonedx.MLModelEnergyConsumptionActivityTraining,
		cyclonedx.MLModelEnergyConsumptionActivityFineTuning,
		cyclonedx.MLModelEnergyConsumptionActivityValidation,
		cyclonedx.MLModelEnergyConsumptionActivityDeployment,
		cyclonedx.MLModelEnergyConsumptionActivityInference:
		return cyclonedx.MLModelEnergyConsumptionActivity(s)
	default:
		return cyclonedx.MLModelEnergyConsumptionActivityOther
	}
}

// ── evidence (§3.8 / §3.9) ──────────────────────────────────────────────────

func evidence(c *airom.Component) *cyclonedx.Evidence {
	ev := &cyclonedx.Evidence{}

	if len(c.Evidence.Occurrences) > 0 {
		occs := make([]cyclonedx.EvidenceOccurrence, 0, len(c.Evidence.Occurrences))
		for _, o := range c.Evidence.Occurrences {
			eo := cyclonedx.EvidenceOccurrence{
				Location:          o.Location.Path, // required by schema
				Symbol:            o.Symbol,
				AdditionalContext: o.Snippet,
			}
			// 1-based line; whole-file (0) omits line entirely (§6.1).
			if o.Location.Line > 0 {
				line := o.Location.Line
				eo.Line = &line
			}
			occs = append(occs, eo)
		}
		ev.Occurrences = &occs
	}

	if len(c.Evidence.Identity) > 0 {
		ids := make([]cyclonedx.EvidenceIdentity, 0, len(c.Evidence.Identity))
		for _, ic := range c.Evidence.Identity {
			ei := cyclonedx.EvidenceIdentity{
				Field:          cyclonedx.EvidenceIdentityFieldType(ic.Field),
				ConcludedValue: ic.Value,
				Confidence:     f32ptr(writer.ConfidenceNumber(ic.Confidence)),
			}
			if len(ic.Methods) > 0 {
				ms := make([]cyclonedx.EvidenceIdentityMethod, 0, len(ic.Methods))
				for _, m := range ic.Methods {
					em := cyclonedx.EvidenceIdentityMethod{
						Technique:  technique(m),
						Confidence: f32ptr(writer.ConfidenceNumber(ic.Confidence)),
					}
					if m == airom.MethodConfig {
						em.Value = "config-analysis" // recovery marker (§5)
					}
					ms = append(ms, em)
				}
				ei.Methods = &ms
			}
			ids = append(ids, ei)
		}
		ev.Identity = &cyclonedx.EvidenceIdentityChoice{Identities: &ids}
	}

	if ev.Occurrences == nil && ev.Identity == nil {
		return nil
	}
	return ev
}

// technique maps a DetectionMethod to a CDX evidence technique (§5): identical
// strings except config-analysis, which has no enum value and becomes "other".
func technique(m airom.DetectionMethod) cyclonedx.EvidenceIdentityTechnique {
	if m == airom.MethodConfig {
		return cyclonedx.EvidenceIdentityTechniqueOther
	}
	return cyclonedx.EvidenceIdentityTechnique(m)
}

// ── properties (§6.5) ───────────────────────────────────────────────────────

func (b *builder) properties(c *airom.Component) *[]cyclonedx.Property {
	var p propList

	// Every component (§3.2).
	p.add("airom:kind", string(c.Kind))
	p.add("airom:confidence", writer.FormatConfidence(c.Confidence))

	// Provider: model kinds vs the rest.
	if prov, ok := c.Provider.Value(); ok {
		if writer.ModelKind(c.Kind) {
			p.add("airom:model.provider", prov)
		} else {
			p.add("airom:provider", prov)
		}
	}

	// ReleaseTime — any component (§3.2).
	if t, ok := c.ReleaseTime.Value(); ok {
		p.add("airom:releaseTime", t.UTC().Format(time.RFC3339))
	}

	// Model facet scalars with no native CDX slot (§3.3).
	if c.Model != nil {
		if v, ok := c.Model.ParamCount.Value(); ok {
			p.add("airom:model.paramCount", strconv.FormatInt(v, 10))
		}
		if v, ok := c.Model.Quantization.Value(); ok {
			p.add("airom:model.quantization", v)
		}
		if v, ok := c.Model.ContextLength.Value(); ok {
			p.add("airom:model.contextLength", strconv.FormatInt(v, 10))
		}
		if v, ok := c.Model.Format.Value(); ok {
			p.add("airom:model.format", v)
		}
		if v, ok := c.Model.BaseModel.Value(); ok {
			p.add("airom:model.baseModel", v)
		}
		// Generation params carry their provenance inline (§3.7).
		for _, bp := range c.Model.GenerationParams {
			p.add("airom:param."+bp.Name, paramValue(bp))
		}
	}

	// Hosted-model lifecycle (the EOL overlay). These are component PROPERTIES,
	// deliberately not a vulnerabilities[] entry: a retirement is a scheduled
	// vendor action, not a defect, and filing it as a vulnerability would put a
	// non-CVE with no CVSS into the array downstream triage and VEX tooling
	// treats as security findings.
	if e := c.EOL; e != nil {
		p.add("airom:eol.state", string(e.State))
		if e.Shutdown != nil {
			p.add("airom:eol.shutdownDate", e.Shutdown.String())
		}
		if e.Announced != nil {
			p.add("airom:eol.announcedDate", e.Announced.String())
		}
		if e.DaysRemaining != nil {
			p.add("airom:eol.daysRemaining", strconv.Itoa(*e.DaysRemaining))
		}
		if e.Replacement != "" {
			p.add("airom:eol.replacement", e.Replacement)
			// The target's own state travels with it: advice to migrate onto a
			// model that is itself retired is worse than no advice.
			if e.ReplacementState != "" {
				p.add("airom:eol.replacementState", string(e.ReplacementState))
			}
		}
		// Provenance for the claim, so a reader can audit and date it.
		p.add("airom:eol.source", e.Source)
		if e.SourceURL != "" {
			p.add("airom:eol.sourceUrl", e.SourceURL)
		}
		if e.Verified != nil {
			p.add("airom:eol.verified", e.Verified.String())
		}
	}

	// Legacy pickle properties (§3.3), kept for one release as the inline view
	// of the pickle-import risk; the authoritative home is vulnerabilities[].
	// Derived from c.Risks so the two never disagree.
	for _, r := range c.Risks {
		if r.ID == airom.RiskPickleImport {
			p.add("airom:pickle.risk", string(r.Severity))
			if len(r.Detail) > 0 {
				p.add("airom:pickle.imports", strings.Join(r.Detail, "|"))
			}
		}
	}

	// Data facet scalars (§3.5): the current DataFacet exposes Format and
	// SizeBytes; Format maps to the dataset "types" key (closest home).
	if c.Data != nil {
		if v, ok := c.Data.Format.Value(); ok {
			p.add("airom:dataset.types", v)
		}
		if v, ok := c.Data.SizeBytes.Value(); ok {
			p.add("airom:dataset.size", strconv.FormatInt(v, 10))
		}
	}

	// Infra endpoint (§3.6).
	if c.Infra != nil {
		if v, ok := c.Infra.Endpoint.Value(); ok {
			p.add("airom:service.endpoint", v)
		}
	}

	// Non-dependency, non-trained-on edges (§3.10).
	for _, r := range b.relProps[c.ID] {
		p.add("airom:rel."+string(r.Type), string(r.To)+"@"+writer.FormatConfidence(r.Confidence))
	}

	// Overflow props, verbatim (§3.2) — already airom:-namespaced & registered.
	for _, kv := range c.Props {
		p.add(kv.Name, kv.Value)
	}

	return p.sorted()
}

// paramValue renders a bound generation parameter as "<value> @ <path>:<line>"
// (§3.7); an unbound param (no occurrence) carries just its value.
func paramValue(bp airom.BoundParam) string {
	if bp.Occurrence == nil {
		return bp.Value
	}
	loc := bp.Occurrence.Location
	return fmt.Sprintf("%s @ %s:%d", bp.Value, loc.Path, loc.Line)
}

// ── vulnerabilities (§3.12: the artifact-risk overlay) ──────────────────────

// buildVulnerabilities projects the artifact-risk overlay into CycloneDX
// vulnerabilities[] — one entry per (component, risk). The id is a non-CVE
// AIROM catalog id with a named source (legal per the CDX schema); ratings use
// method "other" (no CVSS is claimed); affects points at the component's
// bom-ref. Deterministic: sorted by (affected bom-ref, risk id).
func buildVulnerabilities(inv *airom.Inventory) []cyclonedx.Vulnerability {
	var vulns []cyclonedx.Vulnerability
	for i := range inv.Components {
		c := &inv.Components[i]
		for _, r := range c.Risks {
			meta := airom.RiskByID(r.ID)
			v := cyclonedx.Vulnerability{
				ID:          string(r.ID),
				Source:      &cyclonedx.Source{Name: "airom", URL: riskDocURL(meta.Slug)},
				Ratings:     &[]cyclonedx.VulnerabilityRating{{Source: &cyclonedx.Source{Name: "airom"}, Severity: cdxSeverity(r.Severity), Method: cyclonedx.ScoringMethodOther}},
				Description: meta.Description,
				Affects:     &[]cyclonedx.Affects{{Ref: string(c.ID)}},
			}
			var props propList
			if r.Occurrence != nil {
				props.add("airom:risk.evidence", riskEvidence(r.Occurrence))
			}
			if len(r.Detail) > 0 {
				props.add("airom:risk.symbols", strings.Join(r.Detail, "|"))
			}
			v.Properties = props.sorted()
			vulns = append(vulns, v)
		}
		// CVEs from the OSV overlay: a real advisory id + CVSSv3 rating (not the
		// "other" method the artifact risks use), affecting this component.
		for _, cve := range c.Vulnerabilities {
			rating := cyclonedx.VulnerabilityRating{
				Source:   &cyclonedx.Source{Name: cve.Source},
				Severity: cdxVulnSeverity(cve.Severity),
			}
			if cve.Vector != "" {
				rating.Method = cdxScoringMethod(cve.Vector)
				rating.Vector = cve.Vector
			}
			if cve.Score > 0 {
				s := cve.Score
				rating.Score = &s
			}
			v := cyclonedx.Vulnerability{
				ID:          cve.ID,
				Source:      &cyclonedx.Source{Name: cve.Source, URL: cve.URL},
				Ratings:     &[]cyclonedx.VulnerabilityRating{rating},
				Description: cve.Summary,
				Affects:     &[]cyclonedx.Affects{{Ref: string(c.ID)}},
			}
			if len(cve.Aliases) > 0 {
				refs := make([]cyclonedx.VulnerabilityReference, 0, len(cve.Aliases))
				for _, a := range cve.Aliases {
					refs = append(refs, cyclonedx.VulnerabilityReference{ID: a, Source: &cyclonedx.Source{Name: "osv.dev"}})
				}
				v.References = &refs
			}
			if cve.Fixed != "" {
				var props propList
				props.add("airom:cve.fixedVersion", cve.Fixed)
				v.Properties = props.sorted()
			}
			vulns = append(vulns, v)
		}
	}
	sort.SliceStable(vulns, func(i, j int) bool {
		ri := (*vulns[i].Affects)[0].Ref
		rj := (*vulns[j].Affects)[0].Ref
		if ri != rj {
			return ri < rj
		}
		return vulns[i].ID < vulns[j].ID
	})
	return vulns
}

// riskDocURL is the stable documentation anchor for a risk slug.
func riskDocURL(slug string) string {
	return "https://github.com/airomhq/airom/blob/main/docs/risks.md#" + slug
}

// riskEvidence renders a risk occurrence as "path:line" (or "path" for a
// whole-file artifact sighting).
func riskEvidence(o *airom.Occurrence) string {
	if o.Location.Line > 0 {
		return fmt.Sprintf("%s:%d", o.Location.Path, o.Location.Line)
	}
	return o.Location.Path
}

// cdxSeverity maps an AIROM severity bucket onto the CycloneDX enum.
func cdxSeverity(s airom.RiskSeverity) cyclonedx.Severity {
	switch s {
	case airom.RiskHigh:
		return cyclonedx.SeverityHigh
	case airom.RiskMedium:
		return cyclonedx.SeverityMedium
	default:
		return cyclonedx.SeverityLow
	}
}

// cdxVulnSeverity maps a CVE severity bucket (which includes critical/unknown).
func cdxVulnSeverity(s airom.VulnSeverity) cyclonedx.Severity {
	switch s {
	case airom.VulnCritical:
		return cyclonedx.SeverityCritical
	case airom.VulnHigh:
		return cyclonedx.SeverityHigh
	case airom.VulnMedium:
		return cyclonedx.SeverityMedium
	case airom.VulnLow:
		return cyclonedx.SeverityLow
	default:
		return cyclonedx.SeverityUnknown
	}
}

// cdxScoringMethod names the CVSS version from the vector prefix so the emitted
// rating.method matches the vector it carries — labeling a CVSS:4.0 or CVSS:2.0
// vector as CVSSv31 would misdirect any consumer that parses per the method.
// AIROM only computes v3 scores, so a v2/v4 vector rides with its text-derived
// severity and no fabricated score.
func cdxScoringMethod(vector string) cyclonedx.ScoringMethod {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		return cyclonedx.ScoringMethodCVSSv31
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		return cyclonedx.ScoringMethodCVSSv3
	case strings.HasPrefix(vector, "CVSS:2.0/") || strings.HasPrefix(vector, "AV:"):
		return cyclonedx.ScoringMethodCVSSv2
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		return cyclonedx.ScoringMethodCVSSv4
	default:
		return cyclonedx.ScoringMethodOther
	}
}

// ── dependencies (§3.10) ────────────────────────────────────────────────────

// buildDependencies collects depends-on edges into dependencies[]{ref,dependsOn}
// (§3.10). Root edges naturally reference the metadata.component bom-ref.
// Refs and dependsOn lists are sorted for determinism (P7).
func buildDependencies(inv *airom.Inventory) []cyclonedx.Dependency {
	byRef := map[airom.ID]map[string]struct{}{}
	for _, r := range inv.Relationships {
		if r.Type != airom.RelDependsOn {
			continue
		}
		if byRef[r.From] == nil {
			byRef[r.From] = map[string]struct{}{}
		}
		byRef[r.From][string(r.To)] = struct{}{}
	}
	if len(byRef) == 0 {
		return nil
	}

	refs := make([]airom.ID, 0, len(byRef))
	for ref := range byRef {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })

	deps := make([]cyclonedx.Dependency, 0, len(refs))
	for _, ref := range refs {
		set := byRef[ref]
		on := make([]string, 0, len(set))
		for to := range set {
			on = append(on, to)
		}
		sort.Strings(on)
		deps = append(deps, cyclonedx.Dependency{Ref: string(ref), Dependencies: &on})
	}
	return deps
}

// ── small helpers ───────────────────────────────────────────────────────────

// propList accumulates CDX properties and emits them sorted by (name, value)
// with duplicates preserved (§6.5, P7).
type propList []cyclonedx.Property

func (p *propList) add(name, value string) {
	*p = append(*p, cyclonedx.Property{Name: name, Value: value})
}

func (p propList) sorted() *[]cyclonedx.Property {
	if len(p) == 0 {
		return nil
	}
	s := []cyclonedx.Property(p)
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Name != s[j].Name {
			return s[i].Name < s[j].Name
		}
		return s[i].Value < s[j].Value
	})
	return &s
}

// f32ptr renders a confidence through the §6.2 rounding and returns a pointer
// for the *float32 CDX fields.
func f32ptr(v float64) *float32 {
	f := float32(v)
	return &f
}
