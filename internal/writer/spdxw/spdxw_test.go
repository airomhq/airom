package spdxw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

// ── Harness ────────────────────────────────────────────────────────────────

func inventory(mut ...func(*airom.Inventory)) *airom.Inventory {
	inv := &airom.Inventory{
		Serial:    "urn:uuid:11111111-2222-3333-4444-555555555555",
		Timestamp: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC),
		Lifecycle: "pre-build",
		Tool:      airom.ToolInfo{Name: "airom", Version: "v0.3.5", Commit: "abc1234"},
		Root:      "airom:0000000000000001",
		Components: []airom.Component{
			{
				ID: "airom:0000000000000001", Kind: airom.KindApplication, Name: "app",
			},
			{
				ID: "airom:00000000000000aa", Kind: airom.KindLibrary, Name: "openai",
				Version:  airom.KnownString("1.51.0"),
				Provider: airom.KnownString("openai"),
				PURL:     "pkg:pypi/openai@1.51.0",
				Licenses: []airom.License{{SPDXID: "Apache-2.0"}},
				Package:  &airom.PackageFacet{Ecosystem: "pypi"},
			},
			{
				ID: "airom:00000000000000bb", Kind: airom.KindHostedLLM, Name: "gpt-4.1",
				Provider: airom.KnownString("openai"),
				Model:    &airom.ModelFacet{Task: airom.KnownString("text-generation")},
			},
		},
		Relationships: []airom.Relationship{
			{From: "airom:0000000000000001", To: "airom:00000000000000aa", Type: airom.RelDependsOn, Confidence: 0.95},
			{From: "airom:0000000000000001", To: "airom:00000000000000bb", Type: airom.RelUses, Confidence: 0.7},
		},
	}
	for _, m := range mut {
		m(inv)
	}
	return inv
}

func render(t *testing.T, inv *airom.Inventory) document {
	t.Helper()
	var buf bytes.Buffer
	if err := New(writer.Options{}).Write(&buf, inv); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return doc
}

// graph re-reads the @graph as maps keyed by spdxId, plus a by-type index.
type graph struct {
	byID   map[string]map[string]any
	byType map[string][]map[string]any
	all    []map[string]any
}

func read(t *testing.T, inv *airom.Inventory) graph {
	t.Helper()
	doc := render(t, inv)
	g := graph{byID: map[string]map[string]any{}, byType: map[string][]map[string]any{}}
	for _, raw := range doc.Graph {
		e, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("graph member is not an object: %#v", raw)
		}
		g.all = append(g.all, e)
		typ, _ := e["type"].(string)
		g.byType[typ] = append(g.byType[typ], e)
		if id, ok := e["spdxId"].(string); ok {
			g.byID[id] = e
		}
		if id, ok := e["@id"].(string); ok {
			g.byID[id] = e
		}
	}
	return g
}

// find returns the single element of a type whose name matches.
func (g graph) find(t *testing.T, typ, name string) map[string]any {
	t.Helper()
	for _, e := range g.byType[typ] {
		if e["name"] == name {
			return e
		}
	}
	t.Fatalf("no %s named %q in the graph", typ, name)
	return nil
}

func comment(e map[string]any) string {
	s, _ := e["comment"].(string)
	return s
}

// ── Document shape ─────────────────────────────────────────────────────────

func TestDocumentShape(t *testing.T) {
	doc := render(t, inventory())
	if doc.Context != contextIRI {
		t.Errorf("@context = %q, want %q", doc.Context, contextIRI)
	}
	g := read(t, inventory())

	ci := g.byID[creationInfoRef]
	if ci == nil {
		t.Fatal("no CreationInfo in the graph")
	}
	if ci["specVersion"] != specVersion {
		t.Errorf("specVersion = %v, want %s", ci["specVersion"], specVersion)
	}
	if ci["created"] != "2026-08-03T12:00:00Z" {
		t.Errorf("created = %v", ci["created"])
	}

	sbom := g.byType["software_Sbom"]
	if len(sbom) != 1 {
		t.Fatalf("want exactly one software_Sbom, got %d", len(sbom))
	}
	if got := sbom[0]["rootElement"]; fmt.Sprint(got) != "[https://github.com/airomhq/airom/spdxdocs/11111111-2222-3333-4444-555555555555#0000000000000001]" {
		t.Errorf("rootElement = %v", got)
	}
	if n := len(sbom[0]["element"].([]any)); n != 3 {
		t.Errorf("SBOM lists %d elements, want one per component (3)", n)
	}
}

// TestRootIsAGraphElement: the CycloneDX writer hoists the root out of
// components[] into metadata.component. SPDX has no such slot — rootElement is
// a REFERENCE — so if the root were also excluded here it would be a dangling
// pointer to an element the document never declared.
func TestRootIsAGraphElement(t *testing.T) {
	g := read(t, inventory())
	rootIRI := "https://github.com/airomhq/airom/spdxdocs/11111111-2222-3333-4444-555555555555#0000000000000001"
	if g.byID[rootIRI] == nil {
		t.Fatal("software_Sbom.rootElement points at an element that is not in @graph")
	}
}

// TestNamespaceIsNotAnUnownedDomain: mapping.md's illustrative example mints
// identifiers under airom.dev, a domain the project does not own. An SPDX
// namespace never has to resolve, which is exactly why minting under someone
// else's name is easy to do and wrong to do.
func TestNamespaceIsNotAnUnownedDomain(t *testing.T) {
	var buf bytes.Buffer
	if err := New(writer.Options{}).Write(&buf, inventory()); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("airom.dev")) {
		t.Error("document mints identifiers under airom.dev, which nobody owns")
	}
}

// ── §4: kind → element class ───────────────────────────────────────────────

func TestKindMapping(t *testing.T) {
	cases := []struct {
		kind    airom.ComponentKind
		class   string
		purpose string
	}{
		{airom.KindHostedLLM, "ai_AIPackage", "model"},
		{airom.KindLocalModelFile, "ai_AIPackage", "model"},
		{airom.KindEmbeddingModel, "ai_AIPackage", "model"},
		{airom.KindDataset, "dataset_DatasetPackage", "data"},
		{airom.KindFramework, "software_Package", "framework"},
		{airom.KindLibrary, "software_Package", "library"},
		{airom.KindPrompt, "software_Package", "data"},
		{airom.KindAIConfig, "software_Package", "configuration"},
		{airom.KindVectorDB, "software_Package", "application"},
		{airom.KindInfra, "software_Package", "application"},
		{airom.KindService, "software_Package", "application"},
		{airom.KindRAGPipeline, "software_Package", "application"},
		{airom.KindApplication, "software_Package", "application"},
	}
	for _, c := range cases {
		t.Run(string(c.kind), func(t *testing.T) {
			class, purpose := classOf(c.kind)
			if class != c.class || purpose != c.purpose {
				t.Errorf("classOf(%s) = (%s, %s), want (%s, %s) per mapping.md §4",
					c.kind, class, purpose, c.class, c.purpose)
			}
		})
	}
}

// TestCoarsenedKindSurvives: five kinds share software_Package/application, so
// the exact kind has to be recoverable — the same guarantee the CycloneDX
// writer makes with the airom:kind property.
func TestCoarsenedKindSurvives(t *testing.T) {
	for _, k := range []airom.ComponentKind{
		airom.KindVectorDB, airom.KindInfra, airom.KindService,
		airom.KindRAGPipeline, airom.KindApplication,
	} {
		inv := inventory(func(i *airom.Inventory) {
			i.Components[1].Kind = k
		})
		e := read(t, inv).find(t, "software_Package", "openai")
		if !strings.Contains(comment(e), "airom:kind "+string(k)) {
			t.Errorf("kind %s coarsened to application with no airom:kind note; comment = %q", k, comment(e))
		}
	}
}

// ── §6.4: the NOASSERTION discipline ───────────────────────────────────────

// TestRequiredFieldsAreNoAssertedNotOmitted is the honesty contract in the
// format that has a word for it. On an ai_AIPackage these four fields are
// required; omitting one produces an invalid document, and — worse — a
// consumer cannot tell an omission from a tool that simply did not look.
func TestRequiredFieldsAreNoAssertedNotOmitted(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components[2].Provider = airom.OptString{} // Unknown
	})
	e := read(t, inv).find(t, "ai_AIPackage", "gpt-4.1")

	if e["software_packageVersion"] != noAssertion {
		t.Errorf("software_packageVersion = %v, want %q", e["software_packageVersion"], noAssertion)
	}
	if e["software_downloadLocation"] != noAssertion {
		t.Errorf("software_downloadLocation = %v, want %q", e["software_downloadLocation"], noAssertion)
	}
	// suppliedBy takes an ELEMENT, so the scalar sentinel would be a type
	// error; the no-assertion is the individual.
	if e["suppliedBy"] != noAssertionElement {
		t.Errorf("suppliedBy = %v, want the NoAssertionElement individual", e["suppliedBy"])
	}
	// releaseTime is a DateTime and cannot carry the string, so the
	// no-assertion can only be a note.
	if !strings.Contains(comment(e), "airom:releaseTime NOASSERTION") {
		t.Errorf("releaseTime silently absent; comment = %q", comment(e))
	}
}

// TestSoftwarePackageDoesNotFabricateNoAssertions: NOASSERTION is only correct
// where the field is required. Stamping it on every optional field would turn
// a compact document into a wall of nothing-known.
func TestSoftwarePackageDoesNotFabricateNoAssertions(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components[1].Version = airom.OptString{}
		i.Components[1].Provider = airom.OptString{}
	})
	e := read(t, inv).find(t, "software_Package", "openai")
	for _, f := range []string{"software_packageVersion", "software_downloadLocation", "suppliedBy"} {
		if _, present := e[f]; present {
			t.Errorf("%s = %v on a software_Package where it is optional and unknown; want it omitted",
				f, e[f])
		}
	}
}

// TestDatasetRequiredFields: dataset_datasetType is a controlled vocabulary
// with 1..* cardinality, so an unknown type is the ENUM MEMBER noAssertion,
// never the scalar sentinel and never an omission.
func TestDatasetRequiredFields(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components = append(i.Components, airom.Component{
			ID: "airom:00000000000000cc", Kind: airom.KindDataset, Name: "corpus",
		})
	})
	e := read(t, inv).find(t, "dataset_DatasetPackage", "corpus")

	types, ok := e["dataset_datasetType"].([]any)
	if !ok || len(types) == 0 {
		t.Fatalf("dataset_datasetType = %v, want 1..* values", e["dataset_datasetType"])
	}
	if types[0] != noAssertionDatasetType {
		t.Errorf("dataset_datasetType = %v, want the enum member %q (not the scalar %q)",
			types[0], noAssertionDatasetType, noAssertion)
	}
	if fmt.Sprint(e["originatedBy"]) != "["+noAssertionElement+"]" {
		t.Errorf("originatedBy = %v, want NoAssertionElement", e["originatedBy"])
	}
	if !strings.Contains(comment(e), "airom:builtTime NOASSERTION") {
		t.Errorf("builtTime silently absent; comment = %q", comment(e))
	}
}

// TestDatasetTypeOnlyWhereSound: a serialization format says what the bytes
// look like, not what the data is. CSV is structured by construction; "where I
// downloaded it from" is not a dataset type and guessing one would put an
// invented claim in a required field.
func TestDatasetTypeOnlyWhereSound(t *testing.T) {
	cases := map[string]string{
		"csv":        "structured",
		"parquet":    "structured",
		"jsonl":      "structured",
		"hf-dataset": noAssertionDatasetType,
		"kaggle":     noAssertionDatasetType,
	}
	for format, want := range cases {
		inv := inventory(func(i *airom.Inventory) {
			i.Components = append(i.Components, airom.Component{
				ID: "airom:00000000000000cc", Kind: airom.KindDataset, Name: "corpus",
				Data: &airom.DataFacet{Format: airom.KnownString(format)},
			})
		})
		e := read(t, inv).find(t, "dataset_DatasetPackage", "corpus")
		got := e["dataset_datasetType"].([]any)[0]
		if got != want {
			t.Errorf("format %q → dataset_datasetType %v, want %q", format, got, want)
		}
		if !strings.Contains(comment(e), "airom:dataset.format "+format) {
			t.Errorf("format %q not retained in the comment: %q", format, comment(e))
		}
	}
}

// ── Version precision ──────────────────────────────────────────────────────

// TestVersionConstraintIsNotAVersion pins the distinction the whole version
// pipeline exists to preserve. Writing ">=1.0,<2" into software_packageVersion
// hands every downstream matcher a string it will treat as a release.
func TestVersionConstraintIsNotAVersion(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components[1].Version = airom.OptString{}
		i.Components[1].VersionConstraint = ">=1.0,<2"
	})
	e := read(t, inv).find(t, "software_Package", "openai")
	if v, present := e["software_packageVersion"]; present {
		t.Errorf("software_packageVersion = %v; a declared range is not a resolved version", v)
	}
	if !strings.Contains(comment(e), "airom:versionConstraint >=1.0,<2") {
		t.Errorf("the range was dropped entirely; comment = %q", comment(e))
	}
}

// TestRequiredVersionWithOnlyAConstraint: on a class where the field is
// required, the answer is NOASSERTION — the range still must not become the
// value.
func TestRequiredVersionWithOnlyAConstraint(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components[2].VersionConstraint = "^4.0"
	})
	e := read(t, inv).find(t, "ai_AIPackage", "gpt-4.1")
	if e["software_packageVersion"] != noAssertion {
		t.Errorf("software_packageVersion = %v, want %q", e["software_packageVersion"], noAssertion)
	}
	if !strings.Contains(comment(e), "airom:versionConstraint ^4.0") {
		t.Errorf("the range was dropped; comment = %q", comment(e))
	}
}

// ── Referential integrity ──────────────────────────────────────────────────

// TestEveryReferenceResolves is the test that would have caught the first
// draft of this writer, which minted an Agent IRI for every supplier and then
// emitted no Agent elements at all — a graph of dangling pointers that still
// looked fine by eye.
func TestEveryReferenceResolves(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components[1].Supplier = &airom.Party{Name: "OpenAI, Inc.", URL: "https://openai.com"}
		i.Components = append(i.Components, airom.Component{
			ID: "airom:00000000000000cc", Kind: airom.KindDataset, Name: "corpus",
			Licenses: []airom.License{{Name: "CC-BY-4.0"}},
		})
	})
	g := read(t, inv)

	refFields := []string{"suppliedBy", "originatedBy", "from", "to", "createdBy", "createdUsing", "rootElement", "element"}
	for _, e := range g.all {
		for _, f := range refFields {
			for _, ref := range refsIn(e[f]) {
				if ref == noAssertionElement {
					continue // a defined SPDX individual, not a document element
				}
				if g.byID[ref] == nil {
					t.Errorf("%v.%s points at %q, which is not in @graph", e["spdxId"], f, ref)
				}
			}
		}
	}
}

func refsIn(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// TestAgentsAreMintedOnce: two components from one supplier must share one
// Agent element, not each get their own.
func TestAgentsAreMintedOnce(t *testing.T) {
	g := read(t, inventory()) // openai appears as provider on two components
	var n int
	for _, e := range g.byType["Organization"] {
		if e["name"] == "openai" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("openai has %d Organization elements, want 1", n)
	}
}

// TestSupplierBeatsProvider: Supplier is a real named party; Provider is the
// vendor namespace AIROM derived. When both exist the explicit one wins.
func TestSupplierBeatsProvider(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components[1].Supplier = &airom.Party{Name: "OpenAI, Inc."}
	})
	g := read(t, inv)
	e := g.find(t, "software_Package", "openai")
	agent := g.byID[e["suppliedBy"].(string)]
	if agent == nil || agent["name"] != "OpenAI, Inc." {
		t.Errorf("suppliedBy resolved to %v, want the explicit Supplier", agent)
	}
}

// ── Licenses ───────────────────────────────────────────────────────────────

func TestDeclaredLicense(t *testing.T) {
	g := read(t, inventory())
	lic := g.byType["simplelicensing_LicenseExpression"]
	if len(lic) != 1 {
		t.Fatalf("want 1 license element, got %d", len(lic))
	}
	if lic[0]["simplelicensing_licenseExpression"] != "Apache-2.0" {
		t.Errorf("expression = %v", lic[0]["simplelicensing_licenseExpression"])
	}
	var found bool
	for _, r := range g.byType["Relationship"] {
		if r["relationshipType"] == "hasDeclaredLicense" {
			found = true
		}
	}
	if !found {
		t.Error("license element emitted with no hasDeclaredLicense edge pointing at it")
	}
}

// TestSharedLicenseIsOneElement: many packages, one Apache-2.0.
func TestSharedLicenseIsOneElement(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components[2].Licenses = []airom.License{{SPDXID: "Apache-2.0"}}
	})
	g := read(t, inv)
	if n := len(g.byType["simplelicensing_LicenseExpression"]); n != 1 {
		t.Errorf("%d license elements for one shared license, want 1", n)
	}
	var edges int
	for _, r := range g.byType["Relationship"] {
		if r["relationshipType"] == "hasDeclaredLicense" {
			edges++
		}
	}
	if edges != 2 {
		t.Errorf("%d hasDeclaredLicense edges, want one per licensed package (2)", edges)
	}
}

// ── §3.10: relationships ───────────────────────────────────────────────────

func TestRelationshipVocabulary(t *testing.T) {
	cases := []struct {
		rel   airom.RelType
		spdx  string
		exact bool
	}{
		{airom.RelDependsOn, "dependsOn", true},
		{airom.RelTrainedOn, "trainedOn", true},
		{airom.RelContains, "contains", true},
		{airom.RelPromptedBy, "hasInput", true},
		{airom.RelDerivedFrom, "descendantOf", true},
		{airom.RelConfigures, "configures", true},
		{airom.RelUses, "other", false},
		{airom.RelServedBy, "other", false},
		{airom.RelQueries, "other", false},
		{airom.RelEmbedsWith, "other", false},
	}
	for _, c := range cases {
		got, exact := spdxRelType(c.rel)
		if got != c.spdx || exact != c.exact {
			t.Errorf("spdxRelType(%s) = (%s, %v), want (%s, %v) per mapping.md §3.10",
				c.rel, got, exact, c.spdx, c.exact)
		}
	}
}

// TestUnmappedRelationshipNamesItself: `other` with no comment is an edge whose
// meaning has been erased. The fallback is defined in mapping.md §1 as
// relationshipType "other" PLUS a comment naming the real type.
func TestUnmappedRelationshipNamesItself(t *testing.T) {
	g := read(t, inventory())
	var checked bool
	for _, r := range g.byType["Relationship"] {
		if r["relationshipType"] != "other" {
			continue
		}
		checked = true
		if !strings.Contains(comment(r), "airom:rel.uses") {
			t.Errorf("an `other` edge does not name its real type; comment = %q", comment(r))
		}
	}
	if !checked {
		t.Fatal("fixture has no unmapped relationship; the test proves nothing")
	}
}

// ── Security profile ───────────────────────────────────────────────────────

func withFindings(i *airom.Inventory) {
	i.Components[1].Vulnerabilities = []airom.Vulnerability{{
		ID: "CVE-2026-1", Severity: airom.VulnCritical, Summary: "Auth bypass",
		Fixed: "1.83.0", Source: "osv.dev", Score: 9.8, Vector: "CVSS:3.1/AV:N",
	}}
	i.Components[2].Risks = []airom.ArtifactRisk{{
		ID: airom.RiskPickleImport, Severity: airom.RiskHigh, Detail: []string{"os.system"},
	}}
}

// TestNeverAssertsNotAffected: the same law the OpenVEX writer is built on.
// AIROM does no reachability analysis, so a not_affected or fixed assessment
// would be an unfounded all-clear — the one output that makes a consumer stop
// looking.
func TestNeverAssertsNotAffected(t *testing.T) {
	g := read(t, inventory(withFindings))
	for _, e := range g.all {
		typ, _ := e["type"].(string)
		if strings.HasPrefix(typ, "security_Vex") && typ != "security_VexAffectedVulnAssessmentRelationship" {
			t.Errorf("emitted %s; only the affected assessment is founded", typ)
		}
	}
	if n := len(g.byType["security_VexAffectedVulnAssessmentRelationship"]); n != 1 {
		t.Errorf("%d affected assessments, want 1", n)
	}
}

// TestFixedVersionIsNotAFixedStatus: Vulnerability.Fixed names an available
// UPSTREAM release. The scanned tree still runs the vulnerable version, so
// turning it into a remediation claim publishes the opposite of the truth.
func TestFixedVersionIsNotAFixedStatus(t *testing.T) {
	g := read(t, inventory(withFindings))
	rel := g.byType["security_VexAffectedVulnAssessmentRelationship"][0]
	if got, _ := rel["security_actionStatement"].(string); !strings.Contains(got, "1.83.0") {
		t.Errorf("action statement = %q, want the upgrade target", got)
	}
	for _, e := range g.all {
		if v, ok := e["security_status"]; ok && v == "fixed" {
			t.Error("an upstream fixed version became a `fixed` status")
		}
	}
}

// TestRiskIsNotPublishedAsAVexVerdict is the distinction that justifies the two
// branches. A CVE was matched because the installed version falls inside an
// advisory's affected range — a genuine affected claim. An ArtifactRisk is
// AIROM's own structural finding: suspicion with evidence, explicitly not a
// verdict. Publishing it as a VEX assessment turns a lead into an accusation.
func TestRiskIsNotPublishedAsAVexVerdict(t *testing.T) {
	g := read(t, inventory(withFindings))

	riskVuln := g.find(t, "security_Vulnerability", string(airom.RiskPickleImport))
	riskID := riskVuln["spdxId"].(string)

	for _, e := range g.byType["security_VexAffectedVulnAssessmentRelationship"] {
		if e["from"] == riskID {
			t.Fatal("an AIROM artifact risk was published as a VEX affected assessment")
		}
	}

	var found bool
	for _, r := range g.byType["Relationship"] {
		if r["relationshipType"] != "hasAssociatedVulnerability" {
			continue
		}
		found = true
		// Core's direction: the from Element is associated with the to
		// Vulnerability. The security profile's assessment subclasses invert
		// this deliberately; a plain Relationship must not.
		if fmt.Sprint(r["to"]) != "["+riskID+"]" {
			t.Errorf("risk association points %v → %v; want package → vulnerability", r["from"], r["to"])
		}
		if !strings.Contains(comment(r), "not a VEX assessment") {
			t.Errorf("risk association does not disclaim being a verdict; comment = %q", comment(r))
		}
	}
	if !found {
		t.Error("the artifact risk produced no association at all")
	}
}

// TestRiskCarriesItsCatalogMeaning: the id alone is an opaque token.
func TestRiskCarriesItsCatalogMeaning(t *testing.T) {
	g := read(t, inventory(withFindings))
	e := g.find(t, "security_Vulnerability", string(airom.RiskPickleImport))
	if e["summary"] != airom.RiskByID(airom.RiskPickleImport).Title {
		t.Errorf("summary = %v, want the catalog title", e["summary"])
	}
	if d, _ := e["description"].(string); !strings.Contains(d, "os.system") {
		t.Errorf("description = %q, want the specific symbols found", d)
	}
}

// ── Documented losses stay visible (P6) ────────────────────────────────────

// TestEvidenceLossIsStated: SPDX has no occurrence slot, which is the single
// largest loss in this format. A reader who gets an evidence-free document and
// no notice would conclude AIROM found no evidence.
func TestEvidenceLossIsStated(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components[1].Evidence.Occurrences = []airom.Occurrence{
			{Location: airom.Location{Path: "requirements.txt", Line: 3}, DetectorID: "manifest/pypi"},
			{Location: airom.Location{Path: "src/app.py", Line: 1}, DetectorID: "rules/openai/import"},
		}
	})
	g := read(t, inv)
	if c := comment(g.find(t, "software_Package", "openai")); !strings.Contains(c, "airom:evidence 2 occurrence(s)") {
		t.Errorf("occurrence count not stated; comment = %q", c)
	}
	if c := comment(g.byType["software_Sbom"][0]); !strings.Contains(c, "no evidence slot") {
		t.Errorf("the SBOM does not explain the evidence loss; comment = %q", c)
	}
}

// TestZeroConfidenceIsNotAnAssertion: 0 is the assembler's value for a
// component nothing scored (the scan root). "confidence 0" reads as "we looked
// and found no support", which is a different and false claim.
func TestZeroConfidenceIsNotAnAssertion(t *testing.T) {
	e := read(t, inventory()).find(t, "software_Package", "app")
	if strings.Contains(comment(e), "airom:confidence") {
		t.Errorf("unscored root carries a confidence claim; comment = %q", comment(e))
	}
}

// TestTestScopeSurvives: CycloneDX has `scope: excluded` for this and SPDX has
// nothing, so a consumer reading a fixture as a production dependency draws
// exactly the wrong conclusion from an otherwise correct document.
func TestTestScopeSurvives(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) { i.Components[1].TestOnly = true })
	e := read(t, inv).find(t, "software_Package", "openai")
	if !strings.Contains(comment(e), "airom:testOnly true") {
		t.Errorf("test scope dropped; comment = %q", comment(e))
	}
}

// TestModelLifecycleBecomesValidUntilTime: validUntilTime is Core's "do not use
// after" instant, which is exactly what a provider shutdown date is.
func TestModelLifecycleBecomesValidUntilTime(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components[2].EOL = &airom.Lifecycle{
			State:     airom.EOLDeprecated,
			Shutdown:  &airom.Date{Year: 2027, Month: time.March, Day: 1},
			Source:    "airom-catalog",
			SourceURL: "https://platform.openai.com/docs/deprecations",
		}
	})
	e := read(t, inv).find(t, "ai_AIPackage", "gpt-4.1")
	if e["validUntilTime"] != "2027-03-01T00:00:00Z" {
		t.Errorf("validUntilTime = %v, want the shutdown date anchored in UTC", e["validUntilTime"])
	}
	if !strings.Contains(comment(e), "shutdown 2027-03-01") ||
		!strings.Contains(comment(e), "platform.openai.com") {
		t.Errorf("the lifecycle claim is undated and unsourced; comment = %q", comment(e))
	}
}

// TestGenerationParamsAreNotHyperparameters: ai_hyperparameter is training-time
// configuration. An inference-time temperature placed there is a false claim
// about how the model was built.
func TestGenerationParamsAreNotHyperparameters(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components[2].Model.GenerationParams = []airom.BoundParam{{Name: "temperature", Value: "0.2"}}
	})
	e := read(t, inv).find(t, "ai_AIPackage", "gpt-4.1")
	if _, present := e["ai_hyperparameter"]; present {
		t.Error("a generation parameter was emitted as a training hyperparameter")
	}
	if !strings.Contains(comment(e), "airom:param.temperature 0.2") {
		t.Errorf("the parameter was dropped; comment = %q", comment(e))
	}
}

// ── P7: determinism ────────────────────────────────────────────────────────

// TestDeterministic: two renders of one inventory must be byte-identical. The
// hazards here are the two mint-on-reference registries, which are maps.
func TestDeterministic(t *testing.T) {
	inv := inventory(withFindings, func(i *airom.Inventory) {
		i.Components[1].Supplier = &airom.Party{Name: "OpenAI, Inc."}
		i.Components[2].Licenses = []airom.License{{SPDXID: "Apache-2.0"}}
		i.Components = append(i.Components, airom.Component{
			ID: "airom:00000000000000cc", Kind: airom.KindDataset, Name: "corpus",
			Provider: airom.KnownString("huggingface"),
			Licenses: []airom.License{{Name: "CC-BY-4.0"}},
		})
	})
	var first bytes.Buffer
	if err := New(writer.Options{}).Write(&first, inv); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		var next bytes.Buffer
		if err := New(writer.Options{}).Write(&next, inv); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), next.Bytes()) {
			t.Fatalf("render %d differs from the first (P7)", i+1)
		}
	}
}

func TestRegisteredWithTheWriterRegistry(t *testing.T) {
	w, err := writer.New("spdx", writer.Options{})
	if err != nil {
		t.Fatalf("spdx not registered: %v", err)
	}
	if w.Format() != "spdx" {
		t.Errorf("Format() = %q", w.Format())
	}
}

func TestEmptyInventory(t *testing.T) {
	var buf bytes.Buffer
	inv := &airom.Inventory{Timestamp: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)}
	if err := New(writer.Options{}).Write(&buf, inv); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("empty inventory produced invalid JSON: %v", err)
	}
	if len(doc.Graph) == 0 {
		t.Error("empty inventory produced an empty graph; the CreationInfo and SBOM still belong")
	}
}
