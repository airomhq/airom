package conformance

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/internal/writer/writertest"
	"github.com/airomhq/airom/pkg/airom"
)

// Official CycloneDX regex constraints (identical in bom-1.6 and bom-1.7). Kept
// as named constants and independently cross-checked against the schema files
// the cyclonedx-go module ships (TestCDXOfficialPatternsMatchSchema), so they
// stay the *official* patterns rather than a hand-copied guess.
const (
	cdxSerialPattern      = `^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	cdxHashContentPattern = `^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$`
)

var cdxVersions = []string{"1.6", "1.7"}

// ── Deliverable 1: CycloneDX schema conformance ─────────────────────────────

// TestCDXReDecodesCleanly asserts the emitted bytes are well-formed CycloneDX
// that the official library re-decodes without error, with the declared
// SpecVersion and $schema for each requested version. This is the library-level
// validation the task lists as an acceptable path ("use cyclonedx.NewBOMDecoder").
//
// NOTE (validator choice): full JSON-Schema validation of the CDX output would
// use gojsonschema against the module's bom-1.6/1.7 schema. gojsonschema is only
// an indirect, test-scoped dependency here (via cyclonedx-go) and importing it
// directly requires a go.mod require line, which is out of scope for this
// package. The CDX schema is also too rich (anyOf/oneOf/300+ $refs/formats) to
// re-implement faithfully. So schema conformance is covered by (a) this library
// re-decode and (b) the official-pattern checks below, which pin the concrete
// violations. See the package report for the exact gojsonschema error set,
// verified out of tree.
func TestCDXReDecodesCleanly(t *testing.T) {
	for _, ver := range cdxVersions {
		raw := render(t, "cyclonedx", writer.Options{CDXVersion: ver})

		var bom cyclonedx.BOM
		dec := cyclonedx.NewBOMDecoder(strings.NewReader(string(raw)), cyclonedx.BOMFileFormatJSON)
		if err := dec.Decode(&bom); err != nil {
			t.Fatalf("CDX %s: library failed to re-decode emitted BOM: %v", ver, err)
		}
		if bom.BOMFormat != "CycloneDX" {
			t.Errorf("CDX %s: bomFormat = %q", ver, bom.BOMFormat)
		}
		wantSpec := cyclonedx.SpecVersion1_6
		wantSchema := "bom-1.6.schema.json"
		if ver == "1.7" {
			wantSpec, wantSchema = cyclonedx.SpecVersion1_7, "bom-1.7.schema.json"
		}
		if bom.SpecVersion != wantSpec {
			t.Errorf("CDX %s: specVersion = %v", ver, bom.SpecVersion)
		}
		if !strings.Contains(bom.JSONSchema, wantSchema) {
			t.Errorf("CDX %s: $schema = %q, want reference to %s", ver, bom.JSONSchema, wantSchema)
		}
	}
}

// knownCDXPatternViolations is the allow-list of CDX official-pattern
// violations the current fixture may provoke. TestCDXOfficialPatternConformance
// asserts every observed violation is ON this list (no NEW/undocumented
// violation), while tolerating a violation being fixed — the writer and fixture
// are edited independently of this suite.
//
// FINDING (CDX-2, OPEN) hash content too short — SCHEMA-INVALID. The
// local-model-file component carries Hash{Alg:"SHA-256", Hex:"abcd"} (and purl
// checksum sha256:abcd). "abcd" is 4 hex chars; the official CDX hash pattern
// requires 32/40/64/96/128. The writer emits the digest verbatim, so this is
// bogus fixture data rather than a writer defect, but it makes the CDX document
// schema-invalid. Integrator call (fix the fixture digest) — not fixed here.
//
// FINDING (CDX-1, since RESOLVED) serialNumber doubled urn:uuid: prefix. The
// fixture's Serial is already "urn:uuid:…"; an earlier CDX writer unconditionally
// prepended another "urn:uuid:", yielding "urn:uuid:urn:uuid:…" (invalid). The
// writer now guards the prefix (internal/writer/cdx/cdx.go — prepend only when
// absent), so this no longer appears. It is intentionally NOT on the allow-list:
// were it to regress, this test must fail.
func knownCDXPatternViolations() map[string]bool {
	return map[string]bool{
		`components[airom:2222222222222222].hashes[0].content: "abcd" violates hash pattern`: true,
	}
}

func TestCDXOfficialPatternConformance(t *testing.T) {
	serialRe := regexp.MustCompile(cdxSerialPattern)
	hashRe := regexp.MustCompile(cdxHashContentPattern)
	allow := knownCDXPatternViolations()

	for _, ver := range cdxVersions {
		doc := mustJSONMap(t, render(t, "cyclonedx", writer.Options{CDXVersion: ver}))

		var got []string
		if sn := str(t, doc["serialNumber"]); !serialRe.MatchString(sn) {
			got = append(got, "serialNumber: "+strconv.Quote(sn)+" violates urn:uuid pattern")
		}
		for _, c := range arr(t, doc["components"]) {
			cm := obj(t, c)
			hashes, ok := cm["hashes"].([]any)
			if !ok {
				continue
			}
			ref := str(t, cm["bom-ref"])
			for i, h := range hashes {
				content := str(t, obj(t, h)["content"])
				if !hashRe.MatchString(content) {
					got = append(got, "components["+ref+"].hashes["+strconv.Itoa(i)+"].content: "+strconv.Quote(content)+" violates hash pattern")
				}
			}
		}
		sort.Strings(got)

		for _, g := range got {
			if !allow[g] {
				t.Errorf("CDX %s: undocumented official-pattern violation (new regression): %s", ver, g)
			}
		}
		t.Logf("CDX %s: %d official-pattern violation(s), all documented: %v", ver, len(got), got)
	}
}

// TestCDXOfficialPatternsMatchSchema proves the constants above are the schema's
// own patterns, by loading the bom-1.6/1.7 schema the cyclonedx-go module ships.
// Skips (does not fail) if the module dir cannot be located, so the suite stays
// green in constrained environments; the pattern checks themselves do not depend
// on locating the schema.
func TestCDXOfficialPatternsMatchSchema(t *testing.T) {
	dir, ok := cdxSchemaDir()
	if !ok {
		t.Skip("cannot locate cyclonedx-go module dir (go list unavailable); pattern constants used as-is")
	}
	for _, ver := range cdxVersions {
		schema := mustJSONMap(t, mustReadFile(t, dir+"/schema/bom-"+ver+".schema.json"))
		props := obj(t, schema["properties"])
		if p := str(t, obj(t, props["serialNumber"])["pattern"]); p != cdxSerialPattern {
			t.Errorf("bom-%s serialNumber pattern drift:\n schema:   %s\n constant: %s", ver, p, cdxSerialPattern)
		}
		defs := obj(t, schema["definitions"])
		if p := str(t, obj(t, defs["hash-content"])["pattern"]); p != cdxHashContentPattern {
			t.Errorf("bom-%s hash-content pattern drift:\n schema:   %s\n constant: %s", ver, p, cdxHashContentPattern)
		}
	}
}

// ── Deliverable 2: CycloneDX mapping round-trip (docs/mapping.md §3.10, §4) ──

// kindByRef is the source ComponentKind for each fixture bom-ref, and wantType
// is the coarser CDX type each kind must map to (§4). Together they assert both
// that airom:kind survives verbatim AND that the CDX type projection is correct.
var (
	kindByRef = map[string]airom.ComponentKind{
		"airom:0000000000000000": airom.KindApplication,    // scan root
		"airom:1111111111111111": airom.KindHostedLLM,      // gpt-4.1
		"airom:2222222222222222": airom.KindLocalModelFile, // tiny.gguf
		"airom:3333333333333333": airom.KindFramework,      // langchain
		"airom:4444444444444444": airom.KindDataset,        // squad
		"airom:5555555555555555": airom.KindVectorDB,       // chroma
	}
	wantType = map[airom.ComponentKind]cyclonedx.ComponentType{
		airom.KindHostedLLM:      cyclonedx.ComponentTypeMachineLearningModel,
		airom.KindLocalModelFile: cyclonedx.ComponentTypeMachineLearningModel,
		airom.KindEmbeddingModel: cyclonedx.ComponentTypeMachineLearningModel,
		airom.KindFramework:      cyclonedx.ComponentTypeFramework,
		airom.KindLibrary:        cyclonedx.ComponentTypeLibrary,
		airom.KindDataset:        cyclonedx.ComponentTypeData,
		airom.KindPrompt:         cyclonedx.ComponentTypeData,
		airom.KindAIConfig:       cyclonedx.ComponentTypeData,
		airom.KindVectorDB:       cyclonedx.ComponentTypeApplication,
		airom.KindInfra:          cyclonedx.ComponentTypeApplication,
		airom.KindService:        cyclonedx.ComponentTypeApplication,
		airom.KindRAGPipeline:    cyclonedx.ComponentTypeApplication,
	}
)

const (
	refRoot      = "airom:0000000000000000"
	refModel     = "airom:1111111111111111"
	refWeights   = "airom:2222222222222222"
	refFramework = "airom:3333333333333333"
	refDataset   = "airom:4444444444444444"
	refVecDB     = "airom:5555555555555555"
)

func TestCDXMappingRoundTrip(t *testing.T) {
	var bom cyclonedx.BOM
	if err := json.Unmarshal(render(t, "cyclonedx", writer.Options{}), &bom); err != nil {
		t.Fatalf("re-parse CDX: %v", err)
	}

	// Root is metadata.component and NOT duplicated in components[] (§4).
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("metadata.component missing")
	}
	if bom.Metadata.Component.BOMRef != refRoot {
		t.Errorf("metadata.component bom-ref = %q, want scan root", bom.Metadata.Component.BOMRef)
	}
	if k := propVal(bom.Metadata.Component.Properties, "airom:kind"); k != string(airom.KindApplication) {
		t.Errorf("root airom:kind = %q, want application", k)
	}
	comps := derefComps(bom.Components)
	if c := findComp(comps, refRoot); c != nil {
		t.Error("scan root leaked into components[]")
	}
	if len(comps) != len(kindByRef)-1 {
		t.Errorf("components[] len = %d, want %d (all kinds minus root)", len(comps), len(kindByRef)-1)
	}

	// Every component: airom:kind == source kind, and CDX type == §4 projection.
	for i := range comps {
		c := &comps[i]
		src, ok := kindByRef[c.BOMRef]
		if !ok {
			t.Errorf("unexpected component %q", c.BOMRef)
			continue
		}
		if k := propVal(c.Properties, "airom:kind"); k != string(src) {
			t.Errorf("%s airom:kind = %q, want %q (exact kind must survive the coarse enum)", c.BOMRef, k, src)
		}
		if c.Type != wantType[src] {
			t.Errorf("%s type = %q, want %q for kind %q", c.BOMRef, c.Type, wantType[src], src)
		}
	}

	// depends-on (root→framework) became a dependencies[] entry (§3.10).
	assertDependsOn(t, &bom, refRoot, refFramework)

	// trained-on (model→dataset) became modelCard.modelParameters.datasets[].ref
	// on the model component (§3.10).
	model := findComp(comps, refModel)
	if model == nil {
		t.Fatal("model component missing")
	}
	if model.ModelCard == nil || model.ModelCard.ModelParameters == nil || model.ModelCard.ModelParameters.Datasets == nil {
		t.Fatal("model modelCard.modelParameters.datasets missing (trained-on edge dropped)")
	}
	if ref := (*model.ModelCard.ModelParameters.Datasets)[0].Ref; ref != refDataset {
		t.Errorf("trained-on datasets[0].ref = %q, want dataset id", ref)
	}
	if model.ModelCard.ModelParameters.Task != "text-generation" {
		t.Errorf("model modelCard task = %q", model.ModelCard.ModelParameters.Task)
	}

	// queries (vecdb→model) became an airom:rel.queries property whose value
	// round-trips to <to-bomref>@<confidence> (§3.10). Edge evidence is
	// legitimately dropped; type + endpoints + confidence survive.
	assertQueriesEdge(t, findComp(comps, refVecDB))

	// evidence.occurrences carry file:line; whole-file (line 0) omits the line.
	assertOccurrences(t, model, findComp(comps, refWeights))

	// evidence.identity[].confidence round-trips as a §6.2 number, and the
	// present method (source-code-analysis) maps to the identical technique.
	assertIdentity(t, model)
}

func assertDependsOn(t *testing.T, bom *cyclonedx.BOM, from, to string) {
	t.Helper()
	if bom.Dependencies == nil {
		t.Fatal("dependencies[] missing")
	}
	for _, d := range *bom.Dependencies {
		if d.Ref == from && d.Dependencies != nil {
			for _, on := range *d.Dependencies {
				if on == to {
					return
				}
			}
		}
	}
	t.Errorf("depends-on edge %s→%s not found in dependencies[]", from, to)
}

func assertQueriesEdge(t *testing.T, vecdb *cyclonedx.Component) {
	t.Helper()
	if vecdb == nil {
		t.Fatal("vector-db component missing")
	}
	values := allPropVals(vecdb.Properties, "airom:rel.queries")
	if len(values) == 0 {
		t.Fatal("airom:rel.queries property missing on vector-db")
	}
	// FINDING (CDX-3): the value appears twice. The fixture double-specifies the
	// queries edge — once as a manual Props entry and once as a real
	// Relationship — and the CDX writer emits both. CDX permits duplicate
	// property names, so this is schema-legal, but it is a redundant encoding of
	// one edge worth flagging. We assert every value round-trips correctly and
	// that at least one reproduces the source edge (queries, →model, @0.6).
	matched := false
	for _, v := range values {
		to, conf := parseRel(t, v)
		if to == refModel {
			if conf != 0.6 {
				t.Errorf("airom:rel.queries confidence = %v, want 0.6", conf)
			}
			matched = true
		}
	}
	if !matched {
		t.Errorf("no airom:rel.queries value round-trips to the model edge @0.6; got %v", values)
	}
	if len(values) > 1 {
		t.Logf("FINDING: airom:rel.queries emitted %d times on vector-db (fixture double-encodes the edge)", len(values))
	}
}

// parseRel splits an airom:rel.* value "<to-bomref>@<confidence>" on the last
// '@' and returns the endpoint and confidence.
func parseRel(t *testing.T, v string) (to string, conf float64) {
	t.Helper()
	at := strings.LastIndex(v, "@")
	if at < 0 {
		t.Fatalf("airom:rel value %q missing @confidence", v)
	}
	c, err := strconv.ParseFloat(v[at+1:], 64)
	if err != nil {
		t.Fatalf("airom:rel value %q confidence not a number: %v", v, err)
	}
	return v[:at], c
}

func assertOccurrences(t *testing.T, model, weights *cyclonedx.Component) {
	t.Helper()
	if model.Evidence == nil || model.Evidence.Occurrences == nil {
		t.Fatal("model evidence.occurrences missing")
	}
	for _, o := range *model.Evidence.Occurrences {
		if o.Location != "src/rag.py" {
			t.Errorf("model occurrence location = %q, want src/rag.py", o.Location)
		}
		if o.Line == nil || (*o.Line != 7 && *o.Line != 8) {
			t.Errorf("model occurrence line = %v, want 7 or 8", o.Line)
		}
	}
	if weights == nil || weights.Evidence == nil || weights.Evidence.Occurrences == nil {
		t.Fatal("weights evidence.occurrences missing")
	}
	// Whole-file sighting (models/tiny.gguf, line 0) omits the line.
	wf := (*weights.Evidence.Occurrences)[0]
	if wf.Location != "models/tiny.gguf" || wf.Line != nil {
		t.Errorf("whole-file occurrence = %q line=%v, want models/tiny.gguf with no line", wf.Location, wf.Line)
	}
}

func assertIdentity(t *testing.T, model *cyclonedx.Component) {
	t.Helper()
	if model.Evidence == nil || model.Evidence.Identity == nil || model.Evidence.Identity.Identities == nil {
		t.Fatal("model evidence.identity missing")
	}
	id := (*model.Evidence.Identity.Identities)[0]
	if id.ConcludedValue != "gpt-4.1" {
		t.Errorf("identity concludedValue = %q", id.ConcludedValue)
	}
	if id.Confidence == nil || *id.Confidence != 0.85 {
		t.Errorf("identity confidence = %v, want 0.85 (§6.2 number)", id.Confidence)
	}
	if id.Methods == nil || len(*id.Methods) != 1 {
		t.Fatalf("identity methods = %v", id.Methods)
	}
	if m := (*id.Methods)[0]; m.Technique != cyclonedx.EvidenceIdentityTechnique(airom.MethodSourceCode) {
		t.Errorf("source-code-analysis technique = %q, want identical string", m.Technique)
	}
}

// TestCDXConfigAnalysisTechnique covers the one DetectionMethod that is NOT an
// identity-mapped verbatim string: config-analysis has no CDX technique enum
// value, so it must map to technique "other" with the recovery marker
// methods[].value = "config-analysis" (docs/mapping.md §5). The shared fixture
// has no config-analysis identity claim, so this drives a minimal inventory.
func TestCDXConfigAnalysisTechnique(t *testing.T) {
	const cid = "airom:1234567812345678"
	inv := &airom.Inventory{
		SchemaVersion: "1",
		Tool:          airom.ToolInfo{Name: "airom", Version: "1.0.0"},
		Serial:        "00000000-0000-4000-8000-000000000001", // unprefixed: CDX writer adds urn:uuid:
		Timestamp:     time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC),
		Source:        airom.SourceInfo{Kind: "dir", Target: "/x"},
		Root:          airom.ID(refRoot),
		Components: []airom.Component{
			{ID: airom.ID(refRoot), Kind: airom.KindApplication, Name: "app", Confidence: 1},
			{
				ID: airom.ID(cid), Kind: airom.KindHostedLLM, Name: "m", Confidence: 0.5,
				Evidence: airom.Evidence{Identity: []airom.IdentityClaim{
					{Field: "name", Value: "m", Confidence: 0.5, Methods: []airom.DetectionMethod{airom.MethodConfig}},
				}},
			},
		},
	}

	var bom cyclonedx.BOM
	if err := json.Unmarshal(renderInv(t, "cyclonedx", writer.Options{}, inv), &bom); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	c := findComp(derefComps(bom.Components), cid)
	if c == nil || c.Evidence == nil || c.Evidence.Identity == nil {
		t.Fatal("config-analysis component evidence.identity missing")
	}
	m := (*(*c.Evidence.Identity.Identities)[0].Methods)[0]
	if m.Technique != cyclonedx.EvidenceIdentityTechniqueOther {
		t.Errorf("config-analysis technique = %q, want other", m.Technique)
	}
	if m.Value != "config-analysis" {
		t.Errorf("config-analysis recovery marker methods[].value = %q, want config-analysis", m.Value)
	}
}

// ── CDX test helpers ────────────────────────────────────────────────────────

func derefComps(c *[]cyclonedx.Component) []cyclonedx.Component {
	if c == nil {
		return nil
	}
	return *c
}

func findComp(comps []cyclonedx.Component, ref string) *cyclonedx.Component {
	for i := range comps {
		if comps[i].BOMRef == ref {
			return &comps[i]
		}
	}
	return nil
}

// propVal returns the first value for a CDX property name, or "" if absent.
func propVal(props *[]cyclonedx.Property, name string) string {
	if props == nil {
		return ""
	}
	for _, p := range *props {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func allPropVals(props *[]cyclonedx.Property, name string) []string {
	var out []string
	if props == nil {
		return out
	}
	for _, p := range *props {
		if p.Name == name {
			out = append(out, p.Value)
		}
	}
	return out
}

// cdxSchemaDir locates the cyclonedx-go module's directory (which ships the
// official schema files) via `go list`. Returns false if unavailable.
func cdxSchemaDir() (string, bool) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/CycloneDX/cyclonedx-go").Output()
	if err != nil {
		return "", false
	}
	dir := strings.TrimSpace(string(out))
	return dir, dir != ""
}

// ── evidence.identity[].field is a CLOSED enum ──────────────────────────────

// cdxIdentityFieldEnum is the schema's own allowed set for
// evidence.identity[].field, cross-checked against the shipped schema by
// TestCDXIdentityFieldEnumMatchesSchema below.
var cdxIdentityFieldEnum = map[string]bool{
	"group": true, "name": true, "version": true, "purl": true,
	"cpe": true, "omniborId": true, "swhid": true, "swid": true, "hash": true,
}

// TestCDXIdentityFieldIsInEnum is the regression test for a document that
// re-decoded cleanly and was still schema-invalid. AIROM's claim vocabulary is
// wider than the spec's: versionConstraint records that a manifest declared a
// range while a lockfile resolved the release. The writer passed it straight
// into the typed field, and cyclonedx-go accepted it because the Go type is a
// bare string — so the library re-decode above could never catch it. A real
// scan produced 12 violations across 10 components.
//
// The fixture deliberately carries a component with BOTH a resolved version
// and a declared constraint, so this test cannot pass vacuously.
func TestCDXIdentityFieldIsInEnum(t *testing.T) {
	inv := writertest.BuildFixture()
	// A component resolved to a concrete release by a lockfile, whose manifest
	// declared a range: exactly the shape that produced the invalid field.
	for i := range inv.Components {
		if inv.Components[i].Kind == airom.KindVectorDB {
			inv.Components[i].Evidence.Identity = append(inv.Components[i].Evidence.Identity,
				airom.IdentityClaim{
					Field: "versionConstraint", Value: ">=0.5.0,<0.6", Confidence: 0.95,
					Methods: []airom.DetectionMethod{airom.MethodManifest},
				})
		}
	}
	for _, ver := range cdxVersions {
		raw := renderInv(t, "cyclonedx", writer.Options{CDXVersion: ver}, inv)

		var bom cyclonedx.BOM
		if err := cyclonedx.NewBOMDecoder(strings.NewReader(string(raw)), cyclonedx.BOMFileFormatJSON).
			Decode(&bom); err != nil {
			t.Fatalf("CDX %s: %v", ver, err)
		}
		if bom.Components == nil {
			t.Fatalf("CDX %s: no components", ver)
		}

		sawConstraintClaim := false
		for _, c := range *bom.Components {
			if c.Evidence == nil || c.Evidence.Identity == nil || c.Evidence.Identity.Identities == nil {
				continue
			}
			for _, id := range *c.Evidence.Identity.Identities {
				if !cdxIdentityFieldEnum[string(id.Field)] {
					t.Errorf("CDX %s: %s has evidence.identity[].field = %q, which is not in the schema enum",
						ver, c.Name, id.Field)
				}
			}
			for _, v := range allPropVals(c.Properties, "airom:evidence.versionConstraint") {
				sawConstraintClaim = true
				if v != ">=0.5.0,<0.6" {
					t.Errorf("CDX %s: constraint claim value = %q", ver, v)
				}
			}
		}
		// Dropping the claim from identity[] must not lose it: the whole point
		// of routing rather than deleting.
		if !sawConstraintClaim {
			t.Errorf("CDX %s: the versionConstraint claim vanished; it must travel as a property", ver)
		}
	}
}

// TestCDXIdentityFieldEnumMatchesSchema proves the set above is the schema's
// own, the same way the pattern constants are proven.
func TestCDXIdentityFieldEnumMatchesSchema(t *testing.T) {
	dir, ok := cdxSchemaDir()
	if !ok {
		t.Skip("cannot locate cyclonedx-go module dir")
	}
	for _, ver := range cdxVersions {
		schema := mustJSONMap(t, mustReadFile(t, dir+"/schema/bom-"+ver+".schema.json"))
		defs := obj(t, schema["definitions"])
		field := obj(t, obj(t, defs["componentIdentityEvidence"])["properties"])["field"]
		raw, ok := obj(t, field)["enum"].([]any)
		if !ok {
			t.Fatalf("bom-%s: componentIdentityEvidence.field has no enum", ver)
		}
		got := map[string]bool{}
		for _, v := range raw {
			got[v.(string)] = true
		}
		if len(got) != len(cdxIdentityFieldEnum) {
			t.Errorf("bom-%s enum drift: schema has %d values, constant has %d: %v",
				ver, len(got), len(cdxIdentityFieldEnum), raw)
		}
		for v := range got {
			if !cdxIdentityFieldEnum[v] {
				t.Errorf("bom-%s: schema allows %q, constant does not", ver, v)
			}
		}
	}
}
