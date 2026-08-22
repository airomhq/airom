// Package assemble is the heart of the pipeline (ARCHITECTURE.md §9): the
// single-threaded, deterministic stage that turns detector claims into the
// canonical component graph. It holds three monopolies no detector can
// touch (invariant P4): identity (CanonicalKey → ID), merging
// (keep-and-relate; contested fields become IdentityClaims, never silent
// discards), and confidence (grouped noisy-OR, §9.3).
package assemble

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
	"github.com/airomhq/airom/pkg/airom/purl"
)

// Options parameterizes one assembly.
type Options struct {
	Tool      airom.ToolInfo
	Source    airom.SourceInfo
	Lifecycle string    // "pre-build" | "post-build"
	Serial    string    // injectable for golden tests
	Timestamp time.Time // injectable clock
}

// Build assembles findings into the Inventory. Deterministic (P7): identical
// inputs produce a byte-identical graph at any parallelism, because the
// pipeline feeds findings in a fixed order (phase-1 sorted by path, phase-2 by
// detector-registration slot) and the assembler sorts every accumulated
// collection it keys on. Ordering-independent identity/merge/confidence is
// property-tested (TestOrderIndependence).
func Build(findings []detect.Finding, unknowns []airom.Unknown, stats airom.ScanStats, opts Options) *airom.Inventory {
	a := &assembly{
		byID:     map[airom.ID]*draft{},
		warnings: nil,
	}

	for _, f := range findings {
		a.absorb(f)
	}
	a.foldPackages()
	a.foldModels()

	root := a.mintRoot(opts)
	a.resolveRelations(findings)
	a.promoteParams()

	inv := &airom.Inventory{
		SchemaVersion: "1",
		Tool:          opts.Tool,
		Serial:        opts.Serial,
		Timestamp:     opts.Timestamp,
		Lifecycle:     opts.Lifecycle,
		Source:        opts.Source,
		Root:          root,
		Unknowns:      unknowns,
		Stats:         stats,
	}

	for _, d := range a.byID {
		inv.Components = append(inv.Components, d.finish())
	}
	sort.Slice(inv.Components, func(i, j int) bool { return inv.Components[i].ID < inv.Components[j].ID })

	inv.Components = dropBoundAIConfig(inv.Components)

	inv.Relationships = a.finishRelations()

	sort.Strings(a.warnings)
	inv.Stats.Warnings = append(inv.Stats.Warnings, a.warnings...)
	return inv
}

// dropBoundAIConfig removes ai-config components whose every occurrence
// duplicates a generation parameter ALREADY bound to a model (§9.5).
//
// KindAIConfig means UNBOUND generation params by definition. The aiconfig
// rule pack is the weak standalone-config fallback, but a call-site kwarg is
// line-anchored too, so the same `temperature=0.1` can arrive twice: once as
// a BoundParam on the model (the strong capture_params story) and once as a
// standalone ai-config claim. Emitting both misstates the ontology and
// double-counts the fact. Found by airom-bench Tier S (airomhq/airom#20).
//
// Refusal-first: an occurrence is "the same fact" only when a same-named
// bound param exists in the SAME file within the capture window (§9.5 binds
// within 12 lines of the call). A component with any occurrence outside that
// evidence is kept whole — a settings.py far from every model call is exactly
// what the pack exists for, and dropping real evidence to tidy a duplicate
// would be the worse bug.
func dropBoundAIConfig(comps []airom.Component) []airom.Component {
	const window = 12

	type site struct {
		path string
		line int
	}
	bound := map[string][]site{} // param name -> where a model binds it
	for i := range comps {
		if comps[i].Model == nil {
			continue
		}
		for _, bp := range comps[i].Model.GenerationParams {
			if bp.Occurrence == nil || bp.Occurrence.Location.Path == "" {
				continue
			}
			bound[bp.Name] = append(bound[bp.Name],
				site{bp.Occurrence.Location.Path, bp.Occurrence.Location.Line})
		}
	}
	if len(bound) == 0 {
		return comps
	}

	covered := func(name, path string, line int) bool {
		for _, s := range bound[name] {
			if s.path == path && line >= s.line-window && line <= s.line+window {
				return true
			}
		}
		return false
	}

	out := comps[:0]
	for _, c := range comps {
		if c.Kind != airom.KindAIConfig {
			out = append(out, c)
			continue
		}
		all := len(c.Evidence.Occurrences) > 0
		for _, occ := range c.Evidence.Occurrences {
			if !covered(c.Name, occ.Location.Path, occ.Location.Line) {
				all = false
				break
			}
		}
		if !all {
			out = append(out, c)
		}
	}
	return out
}

// ── Canonical identity (§9.1) ───────────────────────────────────────────────

// CanonicalKey is the identity tuple. Class ≠ Kind: hosted-llm and
// embedding-model share class "hosted-model" so text-embedding-3-large seen
// by an embeddings rule and a generic provider rule collides into ONE
// component (kind resolves by facet precedence). Version is NOT part of
// identity — competing versions are IdentityClaims on one component.
type CanonicalKey struct {
	Class    string
	Provider string
	Name     string
	Disc     string // weights-file: content hash (identity = bytes); package: ecosystem
}

// ID mints the stable identity: "airom:" + hex(sha256(key))[:16].
func (k CanonicalKey) ID() airom.ID {
	h := sha256.Sum256([]byte(k.Class + "\x00" + k.Provider + "\x00" + k.Name + "\x00" + k.Disc))
	return airom.ID("airom:" + hex.EncodeToString(h[:])[:16])
}

// classOf maps kinds to identity classes.
func classOf(kind airom.ComponentKind) string {
	switch kind {
	case airom.KindHostedLLM, airom.KindEmbeddingModel:
		return "hosted-model"
	case airom.KindLocalModelFile:
		return "weights-file"
	case airom.KindFramework, airom.KindLibrary:
		return "package"
	case airom.KindVectorDB:
		return "vecdb"
	case airom.KindPrompt:
		return "prompt"
	case airom.KindDataset:
		return "dataset"
	case airom.KindAIConfig:
		return "ai-config"
	case airom.KindInfra, airom.KindService:
		return "infra"
	case airom.KindRAGPipeline:
		return "rag"
	case airom.KindApplication:
		return "app"
	default:
		return string(kind)
	}
}

// kindPrecedence resolves the component kind when claims of one identity
// class disagree: the more specific facet wins (§9.1).
var kindPrecedence = map[airom.ComponentKind]int{
	airom.KindEmbeddingModel: 3, // beats hosted-llm: an embeddings rule knows more
	airom.KindFramework:      2, // beats library: framework is the more specific role
	airom.KindService:        2, // beats infra
	airom.KindHostedLLM:      1,
	airom.KindLibrary:        1,
	airom.KindInfra:          1,
}

// nameAliases canonicalize the same asset seen under different names —
// typically a client-package name (from a manifest) versus the service's
// short name (from a usage rule). Data-driven per §9.1; keys and values are
// already lowercased. Conservative: only unambiguous same-asset synonyms.
var nameAliases = map[string]string{
	// vector databases: client package -> service
	"chromadb":           "chroma",
	"pinecone-client":    "pinecone",
	"pinecone":           "pinecone",
	"qdrant-client":      "qdrant",
	"weaviate-client":    "weaviate",
	"weaviate-ts-client": "weaviate",
	"pymilvus":           "milvus",
	"milvus":             "milvus",
	"faiss-cpu":          "faiss",
	"faiss-gpu":          "faiss",
	// frameworks: distribution name -> canonical
	"llama-index": "llamaindex",
	"llama_index": "llamaindex",
	"haystack-ai": "haystack",
	"dspy-ai":     "dspy",
	"pyautogen":   "autogen",
	// vendor SDKs: usage-rule / distribution name -> the installed package.
	// "openai declared in requirements.txt; chat.completions.create in code"
	// is ONE library, not two. azure-openai-sdk is deliberately absent: it
	// names the Azure service binding, which has no manifest counterpart.
	"openai-sdk":           "openai",
	"anthropic-sdk":        "anthropic",
	"@anthropic-ai/sdk":    "anthropic",
	"cohere-sdk":           "cohere",
	"cohere-ai":            "cohere",
	"mistralai-sdk":        "mistralai",
	"@mistralai/mistralai": "mistralai",
	"groq-sdk":             "groq",
	"ollama-sdk":           "ollama",
	"voyageai-sdk":         "voyageai",
}

// providerAliases canonicalize one vendor seen under different spellings —
// typically the manifest catalog's display label ("Hugging Face") versus a
// usage rule's slug ("huggingface"). Applied after lowercasing; same
// conservatism as nameAliases.
var providerAliases = map[string]string{
	"hugging face": "huggingface",
	"mistral ai":   "mistral",
	"voyage ai":    "voyage",
	"llama-index":  "llamaindex",
}

// normalizeKey derives the canonical key for one claim (§9.1 normalizer
// chains). Returns the key plus a version claim extracted from the raw name
// (e.g. an OpenAI date suffix) when applicable.
func normalizeKey(c detect.ComponentClaim) (key CanonicalKey, extraVersion string) {
	name := strings.TrimSpace(c.Name)
	provider := strings.ToLower(strings.TrimSpace(c.Provider))
	if canon, ok := providerAliases[provider]; ok {
		provider = canon
	}
	class := classOf(c.Kind)

	switch class {
	case "hosted-model":
		name = strings.ToLower(name)
		// Date-suffixed snapshots identify the same model line:
		// "gpt-4.1-2026-01-14" ⇒ name "gpt-4.1" + version claim.
		if base, date, ok := splitDateSuffix(name); ok {
			name, extraVersion = base, date
		}
	case "package", "vecdb":
		if c.Package != nil && c.Package.Ecosystem == "pypi" {
			name = purl.NormalizePyPI(name)
		} else {
			name = strings.ToLower(name)
		}
		if canon, ok := nameAliases[name]; ok {
			name = canon
		}
	case "weights-file", "prompt", "dataset":
		// Path-shaped names: clean, keep case (paths are identity on
		// case-sensitive systems; the Disc disambiguates anyway).
		name = strings.Trim(name, "/")
	default:
		name = strings.ToLower(name)
	}

	disc := ""
	switch class {
	case "weights-file":
		// Identity = bytes (§9.1): the same GGUF at three paths is ONE
		// component. Fall back to the path when no hash exists, so two
		// DIFFERENT unhashed files never merge by basename.
		if h := sha256Of(c.Hashes); h != "" {
			disc = "sha256:" + h
		} else {
			disc = "path:" + name
		}
	case "package":
		if c.Package != nil {
			disc = c.Package.Ecosystem
		}
	}

	return CanonicalKey{Class: class, Provider: provider, Name: name, Disc: disc}, extraVersion
}

func sha256Of(hashes []airom.Hash) string {
	for _, h := range hashes {
		if strings.EqualFold(h.Alg, "SHA-256") {
			return strings.ToLower(h.Hex)
		}
	}
	return ""
}

// splitDateSuffix recognizes -YYYY-MM-DD snapshot suffixes on hosted model
// ids.
func splitDateSuffix(name string) (base, date string, ok bool) {
	if len(name) < 12 {
		return "", "", false
	}
	tail := name[len(name)-11:]
	if tail[0] != '-' {
		return "", "", false
	}
	d := tail[1:]
	if len(d) != 10 || d[4] != '-' || d[7] != '-' {
		return "", "", false
	}
	for i, r := range d {
		if i == 4 || i == 7 {
			continue
		}
		if r < '0' || r > '9' {
			return "", "", false
		}
	}
	return name[:len(name)-11], d, true
}

// ── Draft components and merging (§9.2) ─────────────────────────────────────

type draft struct {
	key  CanonicalKey
	id   airom.ID
	kind airom.ComponentKind

	name  string // canonical
	group string

	versionClaims []airom.IdentityClaim
	nameClaims    []airom.IdentityClaim

	// constraintClaims are declared ranges, kept apart from versionClaims so
	// a range can never win the version slot. They surface only when nothing
	// resolved this component to a release.
	constraintClaims []airom.IdentityClaim

	provider         string
	licenses         []airom.License
	hashes           []airom.Hash
	downloadLocation airom.OptString

	model *airom.ModelFacet
	data  *airom.DataFacet
	infra *airom.InfraFacet
	pkg   *airom.PackageFacet
	occs  []airom.Occurrence

	// pkgName is the ecosystem-DECLARED distribution name ("@anthropic-ai/sdk",
	// "chromadb") — the name the purl must carry even when the display name
	// canonicalizes through nameAliases; pkg:npm/anthropic names an artifact
	// that does not exist and pkg:npm/groq names somebody else's. Deterministic
	// under shuffle: the lexicographically smallest declared name wins.
	pkgName string

	// risks accumulates the artifact-risk overlay, keyed by RiskID so the same
	// risk seen at two paths (same-hash component) unions rather than duplicates.
	risks map[airom.RiskID]*riskAgg

	facetWarnings []string
}

// riskAgg accumulates one risk across sightings: a deduped detail set and the
// single provenance occurrence, chosen deterministically (smallest path/line/
// detector) so the output is shuffle-stable (P7).
type riskAgg struct {
	detail map[string]bool
	occ    airom.Occurrence
	hasOcc bool
}

// addRisk folds one risk claim into the draft: unions its detail and keeps the
// deterministically-smallest occurrence as provenance.
func (d *draft) addRisk(id airom.RiskID, detail []string, occ airom.Occurrence) {
	if d.risks == nil {
		d.risks = map[airom.RiskID]*riskAgg{}
	}
	a := d.risks[id]
	if a == nil {
		a = &riskAgg{detail: map[string]bool{}}
		d.risks[id] = a
	}
	for _, s := range detail {
		a.detail[s] = true
	}
	if !a.hasOcc || occLess(occ, a.occ) {
		a.occ, a.hasOcc = occ, true
	}
}

// occLess is a TOTAL order over occurrences, so risk provenance is shuffle-
// stable (P7) even when two sightings share a (path, line, detector): the
// remaining fields break every tie. A partial order here would let the
// first-absorbed sighting win, which is finding-order-dependent.
func occLess(a, b airom.Occurrence) bool {
	if a.Location.Path != b.Location.Path {
		return a.Location.Path < b.Location.Path
	}
	if a.Location.Line != b.Location.Line {
		return a.Location.Line < b.Location.Line
	}
	if a.Location.Column != b.Location.Column {
		return a.Location.Column < b.Location.Column
	}
	if a.DetectorID != b.DetectorID {
		return a.DetectorID < b.DetectorID
	}
	if a.Method != b.Method {
		return a.Method < b.Method
	}
	return a.Snippet < b.Snippet
}

type assembly struct {
	byID     map[airom.ID]*draft
	edges    map[string]*airom.Relationship // key: from|type|to
	warnings []string

	// redirects maps a draft ID deleted by foldPackages to its survivor, so
	// relation endpoints minted from raw claims land on a component that
	// still exists. One hop suffices: only disc-less drafts fold, and their
	// disc-bearing targets are never themselves folded.
	redirects map[airom.ID]airom.ID
}

// canonicalID follows a fold redirect, if any.
func (a *assembly) canonicalID(id airom.ID) airom.ID {
	if to, ok := a.redirects[id]; ok {
		return to
	}
	return id
}

func (a *assembly) absorb(f detect.Finding) {
	key, extraVersion := normalizeKey(f.Claim)
	id := key.ID()

	d, ok := a.byID[id]
	if !ok {
		d = &draft{key: key, id: id, kind: f.Claim.Kind, name: key.Name, provider: key.Provider}
		a.byID[id] = d
	}

	// Kind precedence: the more specific facet wins within a class.
	if kindPrecedence[f.Claim.Kind] > kindPrecedence[d.kind] {
		d.kind = f.Claim.Kind
	}

	if f.Claim.Group != "" && d.group == "" {
		d.group = f.Claim.Group
	}

	// Remember the ecosystem-declared distribution name for the purl
	// (smallest-wins for shuffle determinism).
	if f.Claim.Package != nil && f.Claim.Package.Ecosystem != "" {
		if raw := strings.TrimSpace(f.Claim.Name); raw != "" && (d.pkgName == "" || raw < d.pkgName) {
			d.pkgName = raw
		}
	}

	occ := f.Occurrence
	d.occs = append(d.occs, occ)

	// Raw-name variants that normalize to the same identity are preserved
	// as name claims (contested identity is CDX-native; §9.2).
	if raw := strings.TrimSpace(f.Claim.Name); raw != "" && raw != d.name {
		d.nameClaims = append(d.nameClaims, airom.IdentityClaim{
			Field: "name", Value: raw, Confidence: occ.Confidence,
			Methods: []airom.DetectionMethod{occ.Method},
		})
	}
	for _, v := range []string{strings.TrimSpace(f.Claim.Version), extraVersion} {
		if v != "" {
			d.versionClaims = append(d.versionClaims, airom.IdentityClaim{
				Field: "version", Value: v, Confidence: occ.Confidence,
				Methods: []airom.DetectionMethod{occ.Method},
			})
		}
	}
	if vc := strings.TrimSpace(f.Claim.VersionConstraint); vc != "" {
		d.constraintClaims = append(d.constraintClaims, airom.IdentityClaim{
			Field: "versionConstraint", Value: vc, Confidence: occ.Confidence,
			Methods: []airom.DetectionMethod{occ.Method},
		})
	}

	d.licenses = mergeLicenses(d.licenses, f.Claim.Licenses)
	d.hashes = mergeHashes(d.hashes, f.Claim.Hashes)
	if f.Claim.DownloadLocation != "" {
		if _, known := d.downloadLocation.Value(); !known {
			d.downloadLocation = airom.KnownString(f.Claim.DownloadLocation)
		}
	}

	for _, r := range f.Claim.Risks {
		d.addRisk(r.ID, r.Detail, occ)
	}

	a.mergeFacets(d, f.Claim)
}

// foldPackages merges a usage-detected package (no ecosystem, so its
// identity disc is empty) into the manifest-declared component of the same
// name and provider (§9.1: "declared in requirements.txt; used in
// src/rag.py" is ONE component). It folds only when exactly one
// ecosystem-bearing sibling exists — ambiguity (pypi AND npm of the same
// name) is left split, never guessed.
func (a *assembly) foldPackages() {
	// Group package-class drafts by (provider, name).
	type gkey struct{ provider, name string }
	groups := map[gkey][]*draft{}
	for _, d := range a.byID {
		if d.key.Class != "package" {
			continue
		}
		k := gkey{d.key.Provider, d.key.Name}
		groups[k] = append(groups[k], d)
	}

	for _, ds := range groups {
		if len(ds) < 2 {
			continue
		}
		var targets, discless []*draft
		for _, d := range ds {
			if d.key.Disc == "" {
				discless = append(discless, d)
			} else {
				targets = append(targets, d)
			}
		}
		if len(targets) != 1 || len(discless) == 0 {
			continue // no unique home, or nothing to fold
		}
		a.foldInto(targets[0], discless)
	}
}

// foldModels merges a provider-less hosted/embedding-model draft into the
// same-name sibling that DOES name a provider. A model surfaced from a config
// string — MODEL_ID: gpt-4o in a compose/Dockerfile env — knows the id but not
// the vendor; the code/manifest sighting that does is the same model, not a
// second one. Folds only when exactly one provider-bearing sibling exists;
// two vendors sharing a model name is left split rather than guessed. This is
// the hosted-model analog of foldPackages (§9.1).
func (a *assembly) foldModels() {
	groups := map[string][]*draft{}
	for _, d := range a.byID {
		if d.key.Class != "hosted-model" {
			continue
		}
		groups[d.key.Name] = append(groups[d.key.Name], d)
	}

	for name, ds := range groups {
		if len(ds) < 2 {
			continue
		}
		var targets, providerless []*draft
		for _, d := range ds {
			if d.key.Provider == "" {
				providerless = append(providerless, d)
			} else {
				targets = append(targets, d)
			}
		}
		switch {
		case len(targets) == 1 && len(providerless) > 0:
			a.foldInto(targets[0], providerless)
		case len(targets) > 1:
			a.foldByPublisher(name, targets, providerless)
		}
	}
}

// foldByPublisher resolves one model id claimed by several rules with DIFFERENT
// providers — "sentence-transformers/all-MiniLM-L6-v2" arriving both as an
// embedding model (provider sentence-transformers) and, because the same line
// calls from_pretrained, as a hosted LLM (provider huggingface). That is one
// model rendered as two rows whose kinds contradict each other.
//
// The id settles it. An "org/name" checkpoint is published by org, so the draft
// whose provider matches the org is the real one; a rule naming anything else is
// naming the registry it was fetched from or the library that loads it. When no
// draft claims the publisher there is nothing to prefer, so both stand rather
// than one being picked arbitrarily.
func (a *assembly) foldByPublisher(name string, targets, providerless []*draft) {
	org, _, ok := strings.Cut(name, "/")
	if !ok || org == "" {
		return
	}
	var home *draft
	rest := make([]*draft, 0, len(targets)+len(providerless))
	for _, d := range targets {
		if home == nil && strings.EqualFold(d.key.Provider, org) {
			home = d
			continue
		}
		rest = append(rest, d)
	}
	if home == nil {
		return
	}
	rest = append(rest, providerless...)
	// Deterministic fold order (P7): map iteration decided `targets`.
	sort.Slice(rest, func(i, j int) bool { return rest[i].id < rest[j].id })
	a.foldInto(home, rest)
}

// foldInto merges each src draft into dst, deletes it, and records the fold
// redirect so relation endpoints minted from the pre-fold id retarget cleanly.
func (a *assembly) foldInto(dst *draft, srcs []*draft) {
	for _, d := range srcs {
		a.mergeDraft(dst, d)
		delete(a.byID, d.id)
		if a.redirects == nil {
			a.redirects = map[airom.ID]airom.ID{}
		}
		a.redirects[d.id] = dst.id
	}
}

// mergeDraft folds src into dst: occurrences, claims, licenses, hashes, and
// facets. Identity fields (key/id/name) stay dst's.
func (a *assembly) mergeDraft(dst, src *draft) {
	dst.occs = append(dst.occs, src.occs...)
	dst.versionClaims = append(dst.versionClaims, src.versionClaims...)
	dst.constraintClaims = append(dst.constraintClaims, src.constraintClaims...)
	dst.nameClaims = append(dst.nameClaims, src.nameClaims...)
	dst.licenses = mergeLicenses(dst.licenses, src.licenses)
	dst.hashes = mergeHashes(dst.hashes, src.hashes)
	if _, known := dst.downloadLocation.Value(); !known {
		dst.downloadLocation = src.downloadLocation
	}
	if src.group != "" && dst.group == "" {
		dst.group = src.group
	}
	if kindPrecedence[src.kind] > kindPrecedence[dst.kind] {
		dst.kind = src.kind
	}
	if src.pkg != nil {
		if dst.pkg == nil {
			dst.pkg = src.pkg
		} else if dst.pkg.Ecosystem == "" {
			dst.pkg.Ecosystem = src.pkg.Ecosystem
		}
	}
	if src.pkgName != "" && (dst.pkgName == "" || src.pkgName < dst.pkgName) {
		dst.pkgName = src.pkgName
	}
	for id, agg := range src.risks {
		if !agg.hasOcc {
			continue
		}
		dst.addRisk(id, sortedSetKeys(agg.detail), agg.occ)
	}
}

// mergeFacets folds a claim's partial facets in: Known > Unknown > Absent;
// conflicting Known values demote to Unknown with a warning (§9.2).
func (a *assembly) mergeFacets(d *draft, c detect.ComponentClaim) {
	if c.Model != nil {
		if d.model == nil {
			d.model = &airom.ModelFacet{}
		}
		m := d.model
		a.mergeOptString(d, &m.Task, c.Model.Task, "model.task")
		a.mergeOptString(d, &m.Architecture, c.Model.Architecture, "model.architecture")
		a.mergeOptString(d, &m.Quantization, c.Model.Quantization, "model.quantization")
		a.mergeOptString(d, &m.Format, c.Model.Format, "model.format")
		a.mergeOptString(d, &m.BaseModel, c.Model.BaseModel, "model.baseModel")
		a.mergeOptInt64(d, &m.ParamCount, c.Model.ParamCount, "model.paramCount")
		a.mergeOptInt64(d, &m.ContextLength, c.Model.ContextLength, "model.contextLength")
		if c.Model.Card != nil && m.Card == nil {
			m.Card = c.Model.Card
		}
	}
	if c.Data != nil {
		if d.data == nil {
			d.data = &airom.DataFacet{}
		}
		a.mergeOptString(d, &d.data.Format, c.Data.Format, "data.format")
		a.mergeOptInt64(d, &d.data.SizeBytes, c.Data.SizeBytes, "data.sizeBytes")
		a.mergeOptString(d, &d.data.URL, c.Data.URL, "data.url")
	}
	if c.Infra != nil {
		if d.infra == nil {
			d.infra = &airom.InfraFacet{}
		}
		a.mergeOptString(d, &d.infra.Endpoint, c.Infra.Endpoint, "infra.endpoint")
		a.mergeOptString(d, &d.infra.Region, c.Infra.Region, "infra.region")
		a.mergeOptString(d, &d.infra.Deployment, c.Infra.Deployment, "infra.deployment")
	}
	if c.Package != nil {
		if d.pkg == nil {
			d.pkg = &airom.PackageFacet{}
		}
		if c.Package.Ecosystem != "" {
			if d.pkg.Ecosystem == "" {
				d.pkg.Ecosystem = c.Package.Ecosystem
			} else if d.pkg.Ecosystem != c.Package.Ecosystem {
				d.facetWarnings = append(d.facetWarnings,
					fmt.Sprintf("component %s: conflicting package.ecosystem %q vs %q", d.name, d.pkg.Ecosystem, c.Package.Ecosystem))
			}
		}
	}
}

func (a *assembly) mergeOptString(d *draft, dst *airom.OptString, claim, field string) {
	if claim == "" {
		return
	}
	if v, known := dst.Value(); known {
		if v != claim {
			*dst = airom.UnknownString() // conflict: demote, never guess (§9.2)
			a.warnings = append(a.warnings,
				fmt.Sprintf("component %q: conflicting %s claims (%q vs %q) demoted to unknown", d.name, field, v, claim))
		}
		return
	}
	*dst = airom.KnownString(claim)
}

func (a *assembly) mergeOptInt64(d *draft, dst *airom.OptInt64, claim int64, field string) {
	if claim == 0 {
		return
	}
	if v, known := dst.Value(); known {
		if v != claim {
			*dst = airom.UnknownInt64()
			a.warnings = append(a.warnings,
				fmt.Sprintf("component %q: conflicting %s claims (%d vs %d) demoted to unknown", d.name, field, v, claim))
		}
		return
	}
	*dst = airom.KnownInt64(claim)
}

func mergeLicenses(dst, add []airom.License) []airom.License {
	for _, l := range add {
		dup := false
		for _, e := range dst {
			if e == l {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, l)
		}
	}
	return dst
}

func mergeHashes(dst, add []airom.Hash) []airom.Hash {
	for _, h := range add {
		dup := false
		for _, e := range dst {
			if strings.EqualFold(e.Alg, h.Alg) && strings.EqualFold(e.Hex, h.Hex) {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, airom.Hash{Alg: h.Alg, Hex: strings.ToLower(h.Hex)})
		}
	}
	return dst
}

// finish produces the final Component from a draft.
func (d *draft) finish() airom.Component {
	// Sort by the TOTAL occLess order, then dedup by (Path, Line, DetectorID).
	// A total order matters at the tie: two occurrences sharing those three
	// keys but differing in column/method/snippet (e.g. one rule matching a
	// line twice) would otherwise keep an input-order-dependent survivor,
	// breaking P7. occLess is the same order the risk overlay uses.
	sort.SliceStable(d.occs, func(i, j int) bool { return occLess(d.occs[i], d.occs[j]) })
	occs := d.occs[:0:0]
	for i, o := range d.occs {
		if i > 0 {
			p := d.occs[i-1]
			if p.Location.Path == o.Location.Path && p.Location.Line == o.Location.Line && p.DetectorID == o.DetectorID {
				continue
			}
		}
		occs = append(occs, o)
	}

	c := airom.Component{
		ID:               d.id,
		Kind:             d.kind,
		Name:             d.name,
		Group:            d.group,
		Provider:         optFrom(d.provider),
		Licenses:         d.licenses,
		Hashes:           d.hashes,
		DownloadLocation: d.downloadLocation,
		Model:            d.model,
		Data:             d.data,
		Infra:            d.infra,
		Package:          d.pkg,
		Confidence:       assembleConfidence(occs),
		Evidence:         airom.Evidence{Occurrences: occs},
		// Decided here, on the DEDUPED occurrence set, so the verdict matches
		// the evidence the document actually carries.
		TestOnly: airom.OccurrencesAreTestOnly(occs),
	}

	// Version: highest-confidence claim wins; every claim (winner included)
	// is preserved as contested identity (§9.2).
	if len(d.versionClaims) > 0 {
		sortClaims(d.versionClaims)
		c.Version = airom.KnownString(d.versionClaims[0].Value)
		c.Evidence.Identity = append(c.Evidence.Identity, dedupeClaims(d.versionClaims)...)
	}
	// A declared range is reported only when nothing resolved a release. Once
	// a lockfile or an installed distribution has spoken, the range it was
	// resolved FROM is history — but it stays in the identity evidence, so the
	// document still shows what the manifest asked for.
	if len(d.constraintClaims) > 0 {
		sortClaims(d.constraintClaims)
		if _, resolved := c.Version.Value(); !resolved {
			c.VersionConstraint = d.constraintClaims[0].Value
		}
		c.Evidence.Identity = append(c.Evidence.Identity, dedupeClaims(d.constraintClaims)...)
	}
	if len(d.nameClaims) > 0 {
		sortClaims(d.nameClaims)
		c.Evidence.Identity = append(c.Evidence.Identity, dedupeClaims(d.nameClaims)...)
	}

	// purl discipline (§9.4, D9): derived as an OUTPUT of identity.
	switch d.key.Class {
	case "weights-file":
		if h := sha256Of(d.hashes); h != "" {
			c.PURL = purl.Generic(d.name, h)
		}
	case "package":
		if d.pkg != nil && d.pkg.Ecosystem != "" {
			if v, ok := c.Version.Value(); ok {
				// The purl names the DECLARED distribution, not the aliased
				// display name: pkg:npm/anthropic does not exist and
				// pkg:npm/groq is somebody else's package.
				purlName := d.name
				if d.pkgName != "" {
					purlName = d.pkgName
				}
				if p, err := purl.Package(d.pkg.Ecosystem, d.group, purlName, v); err == nil {
					c.PURL = p
				}
			}
		}
	case "hosted-model":
		// NO purl. Identity via bom-ref + airom:model.* properties.
		if d.provider != "" {
			c.Props = append(c.Props, airom.KV{Name: "airom:model.provider", Value: d.provider})
		}
		c.Props = append(c.Props, airom.KV{Name: "airom:model.id", Value: d.name})
	}

	c.Risks = d.finishRisks()

	return c
}

// finishRisks materializes the accumulated risks into the sorted, severity-
// stamped overlay. Order is (ID, then detail) — deterministic under shuffle.
func (d *draft) finishRisks() []airom.ArtifactRisk {
	if len(d.risks) == 0 {
		return nil
	}
	out := make([]airom.ArtifactRisk, 0, len(d.risks))
	for id, agg := range d.risks {
		r := airom.ArtifactRisk{
			ID:       id,
			Severity: airom.RiskByID(id).Severity,
			Detail:   sortedSetKeys(agg.detail),
		}
		if agg.hasOcc {
			occ := agg.occ
			r.Occurrence = &occ
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// sortedSetKeys returns the set's keys sorted — the deterministic detail order.
func sortedSetKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func optFrom(s string) airom.OptString {
	if s == "" {
		return airom.OptString{}
	}
	return airom.KnownString(s)
}

func sortClaims(claims []airom.IdentityClaim) {
	sort.SliceStable(claims, func(i, j int) bool {
		if claims[i].Confidence != claims[j].Confidence {
			return claims[i].Confidence > claims[j].Confidence
		}
		return claims[i].Value < claims[j].Value
	})
}

func dedupeClaims(claims []airom.IdentityClaim) []airom.IdentityClaim {
	out := claims[:0:0]
	seen := map[string]bool{}
	for _, cl := range claims {
		k := cl.Field + "\x00" + cl.Value
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, cl)
	}
	return out
}

// ── Confidence calculus (§9.3) ──────────────────────────────────────────────

// assembleConfidence implements the grouped noisy-OR:
//
//	step 1  per-detector: g_d = max(c_i) + (1−max)·min(0.05·(n_d−1), 0.15)
//	step 2  per-method maxima, noisy-OR across methods: C = 1 − Π(1−m_j)
//	step 3  clamp 0.99 — unless hash-comparison evidence is present (§9.3)
func assembleConfidence(occs []airom.Occurrence) airom.Confidence {
	if len(occs) == 0 {
		return 0
	}
	type dkey struct {
		det    string
		method airom.DetectionMethod
	}
	maxByDet := map[dkey]float64{}
	countByDet := map[dkey]int{}
	for _, o := range occs {
		k := dkey{o.DetectorID, o.Method}
		countByDet[k]++
		if f := float64(o.Confidence); f > maxByDet[k] {
			maxByDet[k] = f
		}
	}

	byMethod := map[airom.DetectionMethod]float64{}
	for k, m := range maxByDet {
		g := m + (1-m)*math.Min(0.05*float64(countByDet[k]-1), 0.15)
		if g > byMethod[k.method] {
			byMethod[k.method] = g
		}
	}

	// Multiply in sorted method order: float multiplication is not
	// associative, so map-iteration order would make the last few bits of
	// the confidence nondeterministic across runs (a P7 violation once
	// writers serialize the float).
	methods := make([]airom.DetectionMethod, 0, len(byMethod))
	for m := range byMethod {
		methods = append(methods, m)
	}
	sort.Slice(methods, func(i, j int) bool { return methods[i] < methods[j] })

	p := 1.0
	hashEvidence := false
	for _, method := range methods {
		p *= 1 - byMethod[method]
		if method == airom.MethodHash || method == airom.MethodAttestation {
			hashEvidence = true
		}
	}
	c := 1 - p
	if !hashEvidence && c > 0.99 {
		c = 0.99
	}
	return airom.Confidence(c)
}

// ── Root, relations, params ─────────────────────────────────────────────────

func (a *assembly) mintRoot(opts Options) airom.ID {
	name := opts.Source.Target
	if i := strings.LastIndexByte(strings.TrimRight(name, "/"), '/'); i >= 0 {
		name = strings.TrimRight(name, "/")[i+1:]
	}
	if name == "" {
		name = "application"
	}
	key := CanonicalKey{Class: "app", Name: strings.ToLower(name)}
	id := key.ID()
	if _, exists := a.byID[id]; !exists {
		a.byID[id] = &draft{key: key, id: id, kind: airom.KindApplication, name: name}
	}
	return id
}

// resolveRelations turns RelationClaims into edges AFTER all components
// exist (§6.1). Unresolvable hints become warnings — never phantom nodes.
func (a *assembly) resolveRelations(findings []detect.Finding) {
	a.edges = map[string]*airom.Relationship{}

	// Lookup tables: (class, normalized name) → candidate IDs.
	byClassName := map[string][]airom.ID{}
	for id, d := range a.byID {
		k := d.key.Class + "\x00" + d.key.Name
		byClassName[k] = append(byClassName[k], id)
	}
	for _, ids := range byClassName {
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	}
	// (path, detectorID) → distinct component IDs, for local_ref
	// resolution. Multiple distinct claims by the referenced rule in one
	// file are AMBIGUOUS and refuse resolution — mirroring lookupByName;
	// binding to whichever claim happened to come last would be a guessed
	// edge (§9.5 refusal-first).
	byPathDetector := map[string][]airom.ID{}
	for _, f := range findings {
		key, _ := normalizeKey(f.Claim)
		k := f.Occurrence.Location.Path + "\x00" + f.Occurrence.DetectorID
		id := a.canonicalID(key.ID()) // a folded claim's component is its fold survivor
		dup := false
		for _, existing := range byPathDetector[k] {
			if existing == id {
				dup = true
				break
			}
		}
		if !dup {
			byPathDetector[k] = append(byPathDetector[k], id)
		}
	}

	for _, f := range findings {
		if len(f.Relations) == 0 {
			continue
		}
		key, _ := normalizeKey(f.Claim)
		from := a.canonicalID(key.ID()) // never mint an edge from a fold-deleted draft

		for _, rel := range f.Relations {
			to, why := a.resolveHint(rel.Target, f, byClassName, byPathDetector)
			if to == "" {
				a.warnings = append(a.warnings, fmt.Sprintf(
					"unresolved %s relation from %q at %s: %s",
					rel.Type, f.Claim.Name, f.Occurrence.Location.Path, why,
				))
				continue
			}
			if to == from {
				continue
			}
			ek := string(from) + "|" + string(rel.Type) + "|" + string(to)
			e, ok := a.edges[ek]
			if !ok {
				e = &airom.Relationship{From: from, To: to, Type: rel.Type}
				a.edges[ek] = e
			}
			e.Evidence = append(e.Evidence, f.Occurrence)
			// Edge confidence: noisy-OR of its sightings, capped.
			c := 1 - (1-float64(e.Confidence))*(1-float64(f.Occurrence.Confidence))
			if c > 0.99 {
				c = 0.99
			}
			e.Confidence = airom.Confidence(c)
		}
	}
}

func (a *assembly) resolveHint(h detect.TargetHint, f detect.Finding, byClassName map[string][]airom.ID, byPathDetector map[string][]airom.ID) (airom.ID, string) {
	switch {
	case h.LocalRef != "":
		ids := byPathDetector[f.Occurrence.Location.Path+"\x00"+localRefDetectorID(h.LocalRef)]
		switch len(ids) {
		case 1:
			return ids[0], ""
		case 0:
			return "", fmt.Sprintf("no same-file claim by %q", h.LocalRef)
		default:
			return "", fmt.Sprintf("ambiguous local_ref %q (%d distinct claims in this file)", h.LocalRef, len(ids))
		}
	case h.FromField != "":
		// A from_field may reference a named group (stored bare) or a
		// capture_params name (stored as "param.<name>", rule-schema.md
		// target-hint form 2).
		val := f.Occurrence.Fields[h.FromField]
		if val == "" {
			val = f.Occurrence.Fields["param."+h.FromField]
		}
		if val == "" {
			return "", fmt.Sprintf("occurrence has no %q field", h.FromField)
		}
		return a.lookupByName(h.Kind, val, byClassName)
	case h.Name != "":
		return a.lookupByName(h.Kind, h.Name, byClassName)
	default:
		return "", "empty target hint"
	}
}

// localRefDetectorID maps a rule-id local_ref to its occurrence DetectorID
// form ("rules/<id>"); non-rule IDs pass through.
func localRefDetectorID(ref string) string {
	if strings.HasPrefix(ref, "rules/") {
		return ref
	}
	if strings.Contains(ref, "/") {
		return "rules/" + ref
	}
	return ref
}

func (a *assembly) lookupByName(kind airom.ComponentKind, rawName string, byClassName map[string][]airom.ID) (airom.ID, string) {
	key, _ := normalizeKey(detect.ComponentClaim{Kind: kind, Name: rawName})
	ids := byClassName[key.Class+"\x00"+key.Name]
	switch len(ids) {
	case 1:
		return ids[0], ""
	case 0:
		return "", fmt.Sprintf("no %s component named %q", kind, rawName)
	default:
		// Refusal over guessing (§9.5): ambiguity never fabricates an edge.
		return "", fmt.Sprintf("ambiguous target %q (%d candidates)", rawName, len(ids))
	}
}

// promoteParams promotes call-site captured params (Occurrence.Fields
// "param.<name>") onto the model component the SAME occurrence names in its
// "model" field (§9.5). Nothing is averaged; nothing is guessed.
func (a *assembly) promoteParams() {
	byClassName := map[string][]airom.ID{}
	for id, d := range a.byID {
		byClassName[d.key.Class+"\x00"+d.key.Name] = append(byClassName[d.key.Class+"\x00"+d.key.Name], id)
	}

	// Iterate drafts in sorted-ID order: appends to a target's param list
	// must not depend on map-iteration order (P7; the final sort's
	// tie-break needs a deterministic starting order for true duplicates).
	ids := make([]airom.ID, 0, len(a.byID))
	for id := range a.byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		d := a.byID[id]
		for _, occ := range d.occs {
			model := occ.Fields["model"]
			if model == "" {
				continue
			}
			var params []string
			for k := range occ.Fields {
				if strings.HasPrefix(k, "param.") {
					params = append(params, k)
				}
			}
			if len(params) == 0 {
				continue
			}
			key, _ := normalizeKey(detect.ComponentClaim{Kind: airom.KindHostedLLM, Name: model})
			ids := byClassName[key.Class+"\x00"+key.Name]
			if len(ids) != 1 {
				continue // refusal-first: no unique model target
			}
			target := a.byID[ids[0]]
			if target.model == nil {
				target.model = &airom.ModelFacet{}
			}
			sort.Strings(params)
			for _, k := range params {
				occCopy := occ
				target.model.GenerationParams = append(target.model.GenerationParams, airom.BoundParam{
					Name:       strings.TrimPrefix(k, "param."),
					Value:      occ.Fields[k],
					Occurrence: &occCopy,
				})
			}
		}
	}

	// Deterministic order + dedup of identical bindings.
	for _, d := range a.byID {
		if d.model == nil || len(d.model.GenerationParams) == 0 {
			continue
		}
		gp := d.model.GenerationParams
		// Total order: the key covers the FULL location (incl. column) and
		// detector, so params differing only by column or detector never
		// fall back to insertion order (P7).
		sort.SliceStable(gp, func(i, j int) bool { return boundParamKey(gp[i]) < boundParamKey(gp[j]) })
		out := gp[:0:0]
		for i, p := range gp {
			if i > 0 && samePar(gp[i-1], p) {
				continue
			}
			out = append(out, p)
		}
		d.model.GenerationParams = out
	}
}

func boundParamKey(p airom.BoundParam) string {
	loc := ""
	if p.Occurrence != nil {
		loc = fmt.Sprintf("%s\x00%08d\x00%08d\x00%s",
			p.Occurrence.Location.Path, p.Occurrence.Location.Line,
			p.Occurrence.Location.Column, p.Occurrence.DetectorID)
	}
	return p.Name + "\x00" + p.Value + "\x00" + loc
}

func samePar(a, b airom.BoundParam) bool {
	if a.Name != b.Name || a.Value != b.Value {
		return false
	}
	al, bl := airom.Location{}, airom.Location{}
	if a.Occurrence != nil {
		al = a.Occurrence.Location
	}
	if b.Occurrence != nil {
		bl = b.Occurrence.Location
	}
	return al == bl
}

func (a *assembly) finishRelations() []airom.Relationship {
	var out []airom.Relationship
	for _, e := range a.edges {
		sort.SliceStable(e.Evidence, func(i, j int) bool {
			if e.Evidence[i].Location.Path != e.Evidence[j].Location.Path {
				return e.Evidence[i].Location.Path < e.Evidence[j].Location.Path
			}
			return e.Evidence[i].Location.Line < e.Evidence[j].Location.Line
		})
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].To < out[j].To
	})
	return out
}
