package diff

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func comp(id, kind, name string, mut ...func(*airom.Component)) airom.Component {
	c := airom.Component{
		ID:         airom.ID(id),
		Kind:       airom.ComponentKind(kind),
		Name:       name,
		Confidence: 0.95,
		Evidence: airom.Evidence{Occurrences: []airom.Occurrence{{
			Location:   airom.Location{Path: "src/agent.py", Line: 42},
			DetectorID: "rules/openai/model-literal",
			Method:     airom.MethodSourceCode,
			Confidence: 0.95,
		}}},
	}
	for _, m := range mut {
		m(&c)
	}
	return c
}

func inv(target string, comps ...airom.Component) *airom.Inventory {
	root := comp("airom:0000000000000000", string(airom.KindApplication), "app")
	return &airom.Inventory{
		SchemaVersion: "1",
		Source:        airom.SourceInfo{Kind: "fs", Target: target},
		Root:          root.ID,
		Components:    append([]airom.Component{root}, comps...),
	}
}

func TestComputeClassifiesAddedRemovedChanged(t *testing.T) {
	oldInv := inv(
		"old",
		comp("airom:00000000000000aa", "framework", "langchain", func(c *airom.Component) {
			c.Version = airom.KnownString("0.2.1")
		}),
		comp("airom:00000000000000bb", "hosted-llm", "gpt-4o"),
	)
	newInv := inv(
		"new",
		comp("airom:00000000000000aa", "framework", "langchain", func(c *airom.Component) {
			c.Version = airom.KnownString("0.3.0")
		}),
		comp("airom:00000000000000cc", "hosted-llm", "gpt-4.1", func(c *airom.Component) {
			c.Provider = airom.KnownString("openai")
		}),
	)

	r := Compute(oldInv, newInv, false)

	if len(r.Added) != 1 || r.Added[0].Name != "gpt-4.1" {
		t.Fatalf("Added = %+v, want exactly gpt-4.1", r.Added)
	}
	if len(r.Removed) != 1 || r.Removed[0].Name != "gpt-4o" {
		t.Fatalf("Removed = %+v, want exactly gpt-4o", r.Removed)
	}
	if len(r.Changed) != 1 {
		t.Fatalf("Changed = %+v, want exactly langchain", r.Changed)
	}
	ch := r.Changed[0]
	if ch.Component.Name != "langchain" || len(ch.Fields) != 1 {
		t.Fatalf("changed fields = %+v, want one version change", ch.Fields)
	}
	if f := ch.Fields[0]; f.Field != "version" || f.Old != "0.2.1" || f.New != "0.3.0" {
		t.Fatalf("field change = %+v", f)
	}
	if r.Unchanged != 0 {
		t.Fatalf("Unchanged = %d, want 0", r.Unchanged)
	}
	if r.Empty() {
		t.Fatal("Empty() = true for a non-empty diff")
	}
}

func TestComputeIgnoresNoise(t *testing.T) {
	// Confidence inside one band and evidence churn are not changes.
	oldInv := inv("t", comp("airom:00000000000000aa", "hosted-llm", "gpt-4.1", func(c *airom.Component) {
		c.Confidence = 0.91
	}))
	newInv := inv("t", comp("airom:00000000000000aa", "hosted-llm", "gpt-4.1", func(c *airom.Component) {
		c.Confidence = 0.97
		c.Evidence.Occurrences = append(c.Evidence.Occurrences, c.Evidence.Occurrences[0])
	}))
	r := Compute(oldInv, newInv, false)
	if !r.Empty() || r.Unchanged != 1 {
		t.Fatalf("want 1 unchanged and no delta, got %+v", r)
	}
}

func TestComputeSurfacesOverlayChanges(t *testing.T) {
	oldInv := inv("t", comp("airom:00000000000000aa", "local-model-file", "model.pt"))
	newInv := inv("t", comp("airom:00000000000000aa", "local-model-file", "model.pt", func(c *airom.Component) {
		c.Risks = []airom.ArtifactRisk{{ID: airom.RiskPickleImport, Severity: "high"}}
	}))
	r := Compute(oldInv, newInv, false)
	if len(r.Changed) != 1 || r.Changed[0].Fields[0].Field != "risks" {
		t.Fatalf("want a risks field change, got %+v", r.Changed)
	}
	if got := r.Changed[0].Fields[0].New; !strings.Contains(got, "AIROM-RISK-PICKLE-IMPORT(high)") {
		t.Fatalf("risks new = %q", got)
	}
}

func TestComputeSkipsRootAndTestOnly(t *testing.T) {
	oldInv := inv("old")
	newInv := inv("new", comp("airom:00000000000000aa", "hosted-llm", "gpt-4.1", func(c *airom.Component) {
		c.TestOnly = true
	}))

	r := Compute(oldInv, newInv, false)
	if !r.Empty() {
		t.Fatalf("root/test-only leaked into the diff: %+v", r)
	}
	if r.TestOnlySkipped != 1 {
		t.Fatalf("TestOnlySkipped = %d, want 1", r.TestOnlySkipped)
	}

	// Opting in counts it.
	r = Compute(oldInv, newInv, true)
	if len(r.Added) != 1 || r.TestOnlySkipped != 0 {
		t.Fatalf("with includeTests want 1 added, got %+v", r)
	}
}

func TestGateComponentsIsAddedPlusChanged(t *testing.T) {
	oldInv := inv(
		"t",
		comp("airom:00000000000000aa", "framework", "langchain", func(c *airom.Component) { c.Version = airom.KnownString("1") }),
		comp("airom:00000000000000bb", "vector-db", "chroma"),
	)
	newInv := inv(
		"t",
		comp("airom:00000000000000aa", "framework", "langchain", func(c *airom.Component) { c.Version = airom.KnownString("2") }),
		comp("airom:00000000000000cc", "hosted-llm", "gpt-4.1"),
	)
	got := Compute(oldInv, newInv, false).GateComponents()
	if len(got) != 2 {
		t.Fatalf("gate set = %+v, want added gpt-4.1 + changed langchain", got)
	}
	names := []string{got[0].Name, got[1].Name}
	if names[0] != "gpt-4.1" || names[1] != "langchain" {
		t.Fatalf("gate names = %v", names)
	}
}

func TestLoadRoundTripAndRejections(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.json")
	b, err := json.Marshal(inv("t", comp("airom:00000000000000aa", "hosted-llm", "gpt-4.1")))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(good)
	if err != nil {
		t.Fatalf("Load(good) = %v", err)
	}
	if len(got.Components) != 2 || got.Source.Target != "t" {
		t.Fatalf("loaded inventory = %+v", got)
	}

	cdx := filepath.Join(dir, "bom.json")
	if err := os.WriteFile(cdx, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cdx); err == nil || !strings.Contains(err.Error(), "schemaVersion") {
		t.Fatalf("Load(cyclonedx) = %v, want schemaVersion rejection", err)
	}

	junk := filepath.Join(dir, "junk.json")
	if err := os.WriteFile(junk, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(junk); err == nil {
		t.Fatal("Load(junk) succeeded")
	}

	if _, err := Load(filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("Load(absent) succeeded")
	}
}

func result(t *testing.T) *Result {
	t.Helper()
	oldInv := inv(
		"repo@base",
		comp("airom:00000000000000aa", "framework", "langchain", func(c *airom.Component) { c.Version = airom.KnownString("0.2.1") }),
		comp("airom:00000000000000bb", "vector-db", "chroma"),
	)
	newInv := inv(
		"repo@head",
		comp("airom:00000000000000aa", "framework", "langchain", func(c *airom.Component) { c.Version = airom.KnownString("0.3.0") }),
		comp("airom:00000000000000cc", "hosted-llm", "gpt-4.1", func(c *airom.Component) { c.Provider = airom.KnownString("openai") }),
	)
	r := Compute(oldInv, newInv, false)
	r.OldPath, r.NewPath = "base.json", "head.json"
	return r
}

func TestRenderTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, "table", result(t)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"AIBOM Diff", "repo@base", "repo@head",
		"1 added, 1 removed, 1 changed, 0 unchanged",
		"Added (1)", "Removed (1)", "Changed (1)",
		"gpt-4.1", "chroma", "src/agent.py:42",
		"version", "0.2.1", "0.3.0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderTableEmpty(t *testing.T) {
	var buf bytes.Buffer
	i := inv("t", comp("airom:00000000000000aa", "hosted-llm", "gpt-4.1"))
	if err := Render(&buf, "table", Compute(i, i, false)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No AI changes.") {
		t.Errorf("empty diff table output:\n%s", buf.String())
	}
}

func TestRenderMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, "markdown", result(t)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"## AIBOM diff — `repo@base` → `repo@head`",
		"**1 added · 1 removed · 1 changed** — 0 unchanged.",
		"### Added", "### Removed", "### Changed",
		"| hosted-llm | gpt-4.1 | - | openai | 0.95 | `src/agent.py:42` |",
		"version: `0.2.1` → `0.3.0`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, "json", result(t)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Old     struct{ Path, Target string } `json:"old"`
		Summary struct {
			Added, Removed, Changed, Unchanged int
		} `json:"summary"`
		Added []airom.Component `json:"added"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json output does not parse: %v", err)
	}
	if doc.Old.Path != "base.json" || doc.Old.Target != "repo@base" {
		t.Fatalf("old ref = %+v", doc.Old)
	}
	if doc.Summary.Added != 1 || doc.Summary.Removed != 1 || doc.Summary.Changed != 1 {
		t.Fatalf("summary = %+v", doc.Summary)
	}
	if len(doc.Added) != 1 || doc.Added[0].Name != "gpt-4.1" {
		t.Fatalf("added = %+v", doc.Added)
	}
}

func TestRenderUnknownFormat(t *testing.T) {
	if err := Render(&bytes.Buffer{}, "sarif", result(t)); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestRenderDeterminism(t *testing.T) {
	for _, format := range Formats() {
		var a, b bytes.Buffer
		if err := Render(&a, format, result(t)); err != nil {
			t.Fatal(err)
		}
		if err := Render(&b, format, result(t)); err != nil {
			t.Fatal(err)
		}
		if a.String() != b.String() {
			t.Errorf("%s render is not deterministic", format)
		}
	}
}

// withTool stamps the tooling provenance a real scan records.
func withTool(i *airom.Inventory, version, rulesVersion, rulesHash, eolCatalog string) *airom.Inventory {
	i.Tool = airom.ToolInfo{
		Name: "airom", Version: version,
		RulesVersion: rulesVersion, RulesHash: rulesHash, EOLCatalog: eolCatalog,
	}
	return i
}

// TestProvenanceDriftDetectsEachField: every one of these changes what a scan
// FINDS, so a delta across two of them is not the code's doing. tool.version
// counts as much as the ruleset hash — the docstring region class shipped in
// the Go lexer and changed what every Python rule sees without moving the
// ruleset hash by a byte.
func TestProvenanceDriftDetectsEachField(t *testing.T) {
	base := func() *airom.Inventory {
		return withTool(inv("t"), "0.2.2", "builtin", "abcdef0123456789", "builtin")
	}
	cases := []struct {
		name string
		mut  func(*airom.Inventory)
		want string
	}{
		{"binary", func(i *airom.Inventory) { i.Tool.Version = "0.2.3" }, "airom version"},
		{"ruleset", func(i *airom.Inventory) { i.Tool.RulesVersion = "v1.1.0" }, "ruleset:"},
		{"ruleset hash", func(i *airom.Inventory) { i.Tool.RulesHash = "9999999999999999" }, "ruleset hash"},
		{"lifecycle catalog", func(i *airom.Inventory) { i.Tool.EOLCatalog = "builtin+v1.0.0" }, "lifecycle catalog"},
	}
	for _, tc := range cases {
		newInv := base()
		tc.mut(newInv)
		drift := ProvenanceDrift(base(), newInv)
		if len(drift) == 0 {
			t.Errorf("%s: drift not detected", tc.name)
			continue
		}
		if !strings.Contains(strings.Join(drift, "; "), tc.want) {
			t.Errorf("%s: drift %v does not name %q", tc.name, drift, tc.want)
		}
	}

	// Identical tooling is the normal case — scan base and head in one CI run
	// — and must stay silent, or the warning becomes noise nobody reads.
	if d := ProvenanceDrift(base(), base()); len(d) != 0 {
		t.Errorf("identical tooling must not report drift, got %v", d)
	}
}

// TestDriftIsCarriedOnTheResult: Compute attaches it, so every renderer and
// the gate see the same verdict rather than each deciding for itself.
func TestDriftIsCarriedOnTheResult(t *testing.T) {
	oldInv := withTool(inv("old", comp("airom:00000000000000aa", "hosted-llm", "gpt-4o")), "0.2.2", "builtin", "aaaa", "builtin")
	newInv := withTool(inv("new", comp("airom:00000000000000aa", "hosted-llm", "gpt-4o")), "0.2.2", "v1.1.0", "bbbb", "builtin")

	r := Compute(oldInv, newInv, false)
	if len(r.Drift) == 0 {
		t.Fatal("Compute must attach provenance drift to the Result")
	}
	// The delta itself is still computed and reported — refusing to show it
	// would leave the reader with nothing at all.
	if r.Unchanged != 1 {
		t.Errorf("the diff must still be computed under drift, unchanged = %d", r.Unchanged)
	}

	var buf bytes.Buffer
	if err := Render(&buf, "table", r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Not comparable") {
		t.Errorf("the table must carry the caveat, got:\n%s", buf.String())
	}

	buf.Reset()
	if err := Render(&buf, "markdown", r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "[!WARNING]") {
		t.Error("the markdown PR comment must lead with the warning")
	}

	buf.Reset()
	if err := Render(&buf, "json", r); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ProvenanceDrift []string `json:"provenanceDrift"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.ProvenanceDrift) == 0 {
		t.Error("a machine consumer must see the drift without re-deriving it")
	}
}

func retired(c *airom.Component) {
	shutdown := airom.Date{Year: 2024, Month: 11, Day: 6}
	c.EOL = &airom.Lifecycle{State: airom.EOLRetired, Shutdown: &shutdown, Source: "x", SourceURL: "https://x"}
}

func risky(c *airom.Component) {
	c.Risks = []airom.ArtifactRisk{{ID: airom.RiskUnsafeLoad, Severity: airom.RiskMedium}}
}

func vulnerable(c *airom.Component) {
	c.Vulnerabilities = []airom.Vulnerability{
		{ID: "CVE-1", Severity: airom.VulnHigh},
		{ID: "CVE-2", Severity: airom.VulnCritical},
	}
}

// TestAddedComponentsSurfaceTheirOverlays: the delta answered "what AI
// appeared?" but not "is any of it dead or dangerous?", which is the question
// a reviewer is actually holding. A PR adding a model retired since 2024
// rendered as an ordinary row.
func TestAddedComponentsSurfaceTheirOverlays(t *testing.T) {
	oldInv := inv("old")
	newInv := inv(
		"new",
		comp("airom:00000000000000aa", "hosted-llm", "claude-1.0", retired),
		comp("airom:00000000000000bb", "framework", "torch", risky, vulnerable),
	)
	r := Compute(oldInv, newInv, false)

	for _, tc := range []struct{ format, wants string }{
		{"table", "RISK"},
		{"table", "VULN"},
		{"table", "EOL"},
		{"table", "retired"},
		{"table", "critical (2)"},
		{"table", "medium (1)"},
		{"markdown", "Lifecycle"},
		{"markdown", "retired"},
		{"markdown", "critical (2)"},
	} {
		var buf bytes.Buffer
		if err := Render(&buf, tc.format, r); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), tc.wants) {
			t.Errorf("%s output missing %q:\n%s", tc.format, tc.wants, buf.String())
		}
	}
}

// TestCleanDeltaStaysNarrow: overlay columns are conditional, so a PR that
// adds an ordinary model does not pay for three empty columns.
func TestCleanDeltaStaysNarrow(t *testing.T) {
	r := Compute(inv("old"), inv("new", comp("airom:00000000000000aa", "hosted-llm", "gpt-4o")), false)
	var buf bytes.Buffer
	if err := Render(&buf, "table", r); err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"RISK", "VULN", "EOL"} {
		if strings.Contains(buf.String(), col) {
			t.Errorf("no overlay in the delta, so no %s column:\n%s", col, buf.String())
		}
	}
}

// TestMarkdownTablesAreWellFormed: header, separator, and every row must carry
// the same cell count. The separator is built with strings.Repeat, which
// already emits the trailing delimiter — closing the row again silently
// malforms the table in a PR comment.
func TestMarkdownTablesAreWellFormed(t *testing.T) {
	r := Compute(inv("old"), inv(
		"new",
		comp("airom:00000000000000aa", "hosted-llm", "claude-1.0", retired),
	), false)
	var buf bytes.Buffer
	if err := Render(&buf, "markdown", r); err != nil {
		t.Fatal(err)
	}
	widths := map[int]bool{}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "|") {
			widths[strings.Count(line, "|")] = true
		}
	}
	if len(widths) != 1 {
		t.Errorf("markdown rows disagree on cell count %v:\n%s", widths, buf.String())
	}
}
