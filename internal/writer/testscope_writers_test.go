package writer_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/airomhq/airom/internal/writer"
	_ "github.com/airomhq/airom/internal/writer/cdx"
	_ "github.com/airomhq/airom/internal/writer/nativejson"
	_ "github.com/airomhq/airom/internal/writer/sarifw"
	_ "github.com/airomhq/airom/internal/writer/tablew"
	"github.com/airomhq/airom/pkg/airom"
)

// scopeFixture: one production component, one test-only component, and one
// MIXED component whose evidence straddles both.
func scopeFixture() *airom.Inventory {
	occ := func(p string) airom.Occurrence {
		return airom.Occurrence{
			Location: airom.Location{Path: p, Line: 1}, DetectorID: "rules/openai/chat-call",
			Method: airom.MethodSourceCode, Confidence: 0.8,
		}
	}
	return &airom.Inventory{
		SchemaVersion: "1",
		Tool:          airom.ToolInfo{Name: "airom", Version: "test"},
		Source:        airom.SourceInfo{Kind: "dir", Target: "/x"},
		Components: []airom.Component{
			{
				ID: "airom:prod", Kind: airom.KindHostedLLM, Name: "gpt-4o",
				Confidence: 0.9, Evidence: airom.Evidence{Occurrences: []airom.Occurrence{occ("app.py")}},
			},
			{
				ID: "airom:testonly", Kind: airom.KindHostedLLM, Name: "gpt-4-32k",
				Confidence: 0.9, TestOnly: true,
				Evidence: airom.Evidence{Occurrences: []airom.Occurrence{occ("tests/test_app.py")}},
			},
			{
				ID: "airom:mixed", Kind: airom.KindLibrary, Name: "openai",
				Confidence: 0.9,
				Evidence: airom.Evidence{Occurrences: []airom.Occurrence{
					occ("app.py"), occ("tests/test_app.py"), occ("testdata/golden.py"),
				}},
				// A risk whose OWN provenance is a test file. Risks do not travel
				// in Evidence.Occurrences, so a writer that prunes only the
				// occurrence list still emits a security alert inside tests/.
				Risks: []airom.ArtifactRisk{{
					ID: airom.RiskUnsafeLoad, Severity: airom.RiskHigh,
					Occurrence: &airom.Occurrence{
						Location:   airom.Location{Path: "tests/test_app.py", Line: 9},
						DetectorID: "rules/torch/unsafe-load", Method: airom.MethodSourceCode,
					},
				}},
			},
		},
	}
}

func render(t *testing.T, format string, o writer.Options) string {
	t.Helper()
	w, err := writer.New(format, o)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := w.Write(&buf, scopeFixture()); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// TestTableHidesTestOnlyAndSaysSo: filtering silently would make a narrow scan
// indistinguishable from a thorough one — the same dishonesty as reporting
// fixtures as production AI, pointed the other way.
func TestTableHidesTestOnlyAndSaysSo(t *testing.T) {
	out := render(t, "table", writer.Options{})
	if strings.Contains(out, "gpt-4-32k") {
		t.Error("a test-only component must not appear in the default table")
	}
	if !strings.Contains(out, "gpt-4o") {
		t.Error("production components must still appear")
	}
	if !strings.Contains(out, "1 component(s) found only in test scaffolding") {
		t.Errorf("the table must state what it omitted, got:\n%s", out)
	}
	// The mixed component stays, but counts only its production sightings —
	// "3 occ" would be counting evidence the reader is not being shown.
	if !strings.Contains(out, "1 occ") || strings.Contains(out, "3 occ") {
		t.Errorf("mixed component should report 1 production occurrence, got:\n%s", out)
	}

	wide := render(t, "table", writer.Options{IncludeTests: true})
	if !strings.Contains(wide, "gpt-4-32k") {
		t.Error("--include-tests must show test-only components")
	}
	if strings.Contains(wide, "found only in test scaffolding") {
		t.Error("nothing was hidden, so there is nothing to announce")
	}
}

// TestCycloneDXScopesRatherThanDrops: a bill of materials that quietly omits
// things is worth less than one that scopes them. CycloneDX has a field for
// exactly this, so use it instead of inventing a filter.
func TestCycloneDXScopesRatherThanDrops(t *testing.T) {
	var doc struct {
		Components []struct {
			Name  string `json:"name"`
			Scope string `json:"scope"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(render(t, "cyclonedx", writer.Options{})), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range doc.Components {
		got[c.Name] = c.Scope
	}
	if got["gpt-4-32k"] != "excluded" {
		t.Errorf("test-only component scope = %q, want excluded", got["gpt-4-32k"])
	}
	if got["gpt-4o"] == "excluded" {
		t.Error("a production component must not be scoped out")
	}
	if len(doc.Components) != 3 {
		t.Errorf("CycloneDX must carry ALL %d components; scoping is not dropping", 3)
	}
}

// TestSARIFDropsTestOccurrences: SARIF drives code-scanning alerts, so its cost
// of noise is the highest of any output — an alert on a fixture is a
// notification a human must dismiss, and enough of them train the team to
// dismiss the real ones. Component-level filtering alone is not enough: a real
// dependency that also appears in fixtures would still plant alerts there.
func TestSARIFDropsTestOccurrences(t *testing.T) {
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(render(t, "sarif", writer.Options{})), &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Runs[0].Results {
		for _, l := range r.Locations {
			if uri := l.PhysicalLocation.ArtifactLocation.URI; airom.IsTestPath(uri) {
				t.Errorf("SARIF placed a result in test scaffolding: %s", uri)
			}
		}
	}
	if len(doc.Runs[0].Results) == 0 {
		t.Error("production results must survive the filter")
	}
}

// TestWritersDoNotMutateTheInventory: tablew and sarifw prune occurrences on
// what they believe are copies. If a slice header were ever shared back, a
// multi-output run (-o table -o json) would silently ship a JSON document with
// evidence deleted — a corruption no golden would catch, because the goldens
// render one format at a time.
func TestWritersDoNotMutateTheInventory(t *testing.T) {
	inv := scopeFixture()
	before := len(inv.Components[2].Evidence.Occurrences) // the mixed component
	beforeRisks := len(inv.Components[2].Risks)

	for _, format := range []string{"table", "sarif", "cyclonedx", "json"} {
		w, err := writer.New(format, writer.Options{})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := w.Write(&buf, inv); err != nil {
			t.Fatal(err)
		}
		if got := len(inv.Components[2].Evidence.Occurrences); got != before {
			t.Fatalf("%s writer mutated the inventory: %d occurrences left, want %d", format, got, before)
		}
		if got := len(inv.Components[2].Risks); got != beforeRisks {
			t.Fatalf("%s writer mutated the inventory's risks: %d left, want %d", format, got, beforeRisks)
		}
	}
}
