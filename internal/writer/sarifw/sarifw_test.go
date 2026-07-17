package sarifw_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Roro1727/airom/internal/writer"
	"github.com/Roro1727/airom/internal/writer/sarifw"
	"github.com/Roro1727/airom/pkg/airom"
)

var update = flag.Bool("update", false, "update golden files")

// sample builds a representative inventory: an app root (excluded), a hosted
// model with two occurrences under distinct detectors (one carrying a UTF-16
// column), a local weights file with a whole-file occurrence and pickle risk,
// two Unknowns (one whole pipeline stage with no path), and git/dir source
// provenance.
func sample() *airom.Inventory {
	rootID := airom.ID("airom:0000000000000000")
	return &airom.Inventory{
		SchemaVersion: "1",
		Tool:          airom.ToolInfo{Name: "airom", Version: "1.2.3", Commit: "deadbeef"},
		Serial:        "11111111-2222-3333-4444-555555555555",
		Timestamp:     time.Date(2026, 7, 16, 12, 30, 0, 0, time.UTC),
		Lifecycle:     "pre-build",
		Source: airom.SourceInfo{
			Kind:   "dir",
			Target: "/home/user/proj",
			Git:    &airom.GitInfo{Remote: "https://github.com/acme/proj", Commit: "abc123def456"},
		},
		Root: rootID,
		Components: []airom.Component{
			{
				ID:   rootID,
				Kind: airom.KindApplication,
				Name: "proj",
				Evidence: airom.Evidence{Occurrences: []airom.Occurrence{
					{Location: airom.Location{Path: "go.mod", Line: 1}, DetectorID: "rules/root/app", Method: airom.MethodManifest, Confidence: 1},
				}},
			},
			{
				ID:         airom.ID("airom:aaaa111122223333"),
				Kind:       airom.KindHostedLLM,
				Name:       "gpt-4.1",
				Group:      "openai",
				Provider:   airom.KnownString("openai"),
				Confidence: 0.9,
				Evidence: airom.Evidence{Occurrences: []airom.Occurrence{
					{
						Location:   airom.Location{Path: "src/app.py", Line: 12, EndLine: 12, Column: 5, EndColumn: 21},
						DetectorID: "rules/openai/model-literal",
						Method:     airom.MethodSourceCode,
						Confidence: 0.8,
						Snippet:    `model="gpt-4.1"`,
						Symbol:     "chat",
					},
					{
						Location:   airom.Location{Path: "src/util.py", Line: 40},
						DetectorID: "rules/openai/sdk-import",
						Method:     airom.MethodManifest,
						Confidence: 0.7,
					},
				}},
			},
			{
				ID:         airom.ID("airom:bbbb444455556666"),
				Kind:       airom.KindLocalModelFile,
				Name:       "llama-3-8b",
				Version:    airom.KnownString("q4_k_m"),
				Provider:   airom.KnownString("local"),
				PURL:       "pkg:generic/llama-3-8b?checksum=sha256:00ff",
				Confidence: 1,
				Model:      &airom.ModelFacet{PickleRisk: &airom.PickleRisk{Globals: []string{"os.system", "builtins.eval"}}},
				Evidence: airom.Evidence{Occurrences: []airom.Occurrence{
					{
						Location:   airom.Location{Path: "models/llama.gguf", Line: 0},
						DetectorID: "rules/gguf/header",
						Method:     airom.MethodBinary,
						Confidence: 1,
					},
				}},
			},
		},
		Unknowns: []airom.Unknown{
			{Path: "data/weird.bin", DetectorID: "rules/gguf/header", Reason: "truncated GGUF header"},
			{Path: "", DetectorID: "walk", Reason: "permission denied"},
		},
	}
}

func render(t *testing.T, strict bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := sarifw.New(writer.Options{SARIFStrict: strict})
	if err := w.Write(&buf, sample()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.Bytes()
}

func TestFormat(t *testing.T) {
	if got := sarifw.New(writer.Options{}).Format(); got != "sarif" {
		t.Fatalf("Format() = %q, want sarif", got)
	}
}

// report is a minimal typed view for assertions.
type report struct {
	Schema string `json:"$schema"`
	Runs   []struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				InformationURI string `json:"informationUri"`
				Rules          []struct {
					ID                   string                 `json:"id"`
					Name                 string                 `json:"name"`
					DefaultConfiguration struct{ Level string } `json:"defaultConfiguration"`
					Properties           map[string]any         `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		ColumnKind         string `json:"columnKind"`
		OriginalURIBaseIDs map[string]struct {
			URI string `json:"uri"`
		} `json:"originalUriBaseIds"`
		VersionControlProvenance []struct {
			RepositoryURI string `json:"repositoryUri"`
			RevisionID    string `json:"revisionId"`
		} `json:"versionControlProvenance"`
		Invocations []struct {
			ExecutionSuccessful        bool   `json:"executionSuccessful"`
			EndTimeUTC                 string `json:"endTimeUtc"`
			ToolExecutionNotifications []struct {
				Message   struct{ Text string } `json:"message"`
				Level     string                `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Properties map[string]any `json:"properties"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		Results []struct {
			RuleID    string                `json:"ruleId"`
			RuleIndex int                   `json:"ruleIndex"`
			Level     string                `json:"level"`
			Kind      string                `json:"kind"`
			Message   struct{ Text string } `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI       string `json:"uri"`
						URIBaseID string `json:"uriBaseId"`
					} `json:"artifactLocation"`
					Region *json.RawMessage `json:"region"`
				} `json:"physicalLocation"`
				LogicalLocations []struct{ Name string } `json:"logicalLocations"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Properties          map[string]any    `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

func parse(t *testing.T, b []byte) report {
	t.Helper()
	var r report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(r.Runs) != 1 {
		t.Fatalf("want exactly one run, got %d", len(r.Runs))
	}
	return r
}

func TestEnvelope(t *testing.T) {
	r := parse(t, render(t, false))
	run := r.Runs[0]
	if r.Schema != "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json" {
		t.Errorf("bad $schema: %q", r.Schema)
	}
	if run.ColumnKind != "utf16CodeUnits" {
		t.Errorf("columnKind = %q", run.ColumnKind)
	}
	if run.Tool.Driver.Name != "airom" || run.Tool.Driver.InformationURI != "https://github.com/Roro1727/airom" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if got := run.OriginalURIBaseIDs["SRCROOT"].URI; got != "file:///home/user/proj/" {
		t.Errorf("SRCROOT uri = %q", got)
	}
	if len(run.VersionControlProvenance) != 1 || run.VersionControlProvenance[0].RepositoryURI != "https://github.com/acme/proj" || run.VersionControlProvenance[0].RevisionID != "abc123def456" {
		t.Errorf("versionControlProvenance = %+v", run.VersionControlProvenance)
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful || run.Invocations[0].EndTimeUTC != "2026-07-16T12:30:00Z" {
		t.Errorf("invocation = %+v", run.Invocations)
	}
}

func TestOneRulePerDetector(t *testing.T) {
	rules := parse(t, render(t, false)).Runs[0].Tool.Driver.Rules
	// Distinct detectors across non-root components: model-literal,
	// sdk-import, gguf/header. The root's rules/root/app must not appear.
	wantIDs := []string{"rules/gguf/header", "rules/openai/model-literal", "rules/openai/sdk-import"}
	if len(rules) != len(wantIDs) {
		t.Fatalf("rule count = %d, want %d: %+v", len(rules), len(wantIDs), rules)
	}
	for i, r := range rules {
		if r.ID != wantIDs[i] {
			t.Errorf("rule[%d].id = %q, want %q (sorted by id)", i, r.ID, wantIDs[i])
		}
		if r.DefaultConfiguration.Level != "note" {
			t.Errorf("rule[%d] defaultConfiguration.level = %q", i, r.DefaultConfiguration.Level)
		}
		if r.Properties["airom:method"] == nil {
			t.Errorf("rule[%d] missing airom:method", i)
		}
	}
	// UpperCamelCase derivation and method carried from the occurrence.
	if rules[0].Name != "RulesGgufHeader" {
		t.Errorf("rule name = %q, want RulesGgufHeader", rules[0].Name)
	}
	if rules[1].Properties["airom:method"] != "source-code-analysis" {
		t.Errorf("model-literal method = %v", rules[1].Properties["airom:method"])
	}
}

func TestOneResultPerOccurrence(t *testing.T) {
	results := parse(t, render(t, false)).Runs[0].Results
	// 2 (hosted) + 1 (local) = 3; the root occurrence is excluded.
	if len(results) != 3 {
		t.Fatalf("result count = %d, want 3", len(results))
	}
	for _, res := range results {
		if res.RuleID == "rules/root/app" {
			t.Errorf("root occurrence leaked into results: %+v", res)
		}
		// ruleIndex must point at the matching rule id.
		rules := parse(t, render(t, false)).Runs[0].Tool.Driver.Rules
		if rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("ruleIndex %d does not match ruleId %q", res.RuleIndex, res.RuleID)
		}
	}
}

func TestLevelKindToggle(t *testing.T) {
	for _, res := range parse(t, render(t, false)).Runs[0].Results {
		if res.Level != "note" || res.Kind != "" {
			t.Errorf("default: level=%q kind=%q, want note/empty", res.Level, res.Kind)
		}
	}
	for _, res := range parse(t, render(t, true)).Runs[0].Results {
		if res.Kind != "informational" || res.Level != "" {
			t.Errorf("strict: level=%q kind=%q, want empty/informational", res.Level, res.Kind)
		}
	}
}

func TestWholeFileHasNoRegion(t *testing.T) {
	for _, res := range parse(t, render(t, false)).Runs[0].Results {
		phys := res.Locations[0].PhysicalLocation
		if phys.ArtifactLocation.URI == "models/llama.gguf" {
			if phys.Region != nil {
				t.Errorf("whole-file occurrence must omit region, got %s", string(*phys.Region))
			}
			return
		}
	}
	t.Fatal("whole-file result not found")
}

func TestUTF16ColumnAndSnippet(t *testing.T) {
	for _, res := range parse(t, render(t, false)).Runs[0].Results {
		phys := res.Locations[0].PhysicalLocation
		if phys.ArtifactLocation.URI != "src/app.py" {
			continue
		}
		if phys.ArtifactLocation.URIBaseID != "SRCROOT" {
			t.Errorf("uriBaseId = %q", phys.ArtifactLocation.URIBaseID)
		}
		var reg struct {
			StartLine, StartColumn, EndLine, EndColumn int
			Snippet                                    struct{ Text string }
		}
		if phys.Region == nil {
			t.Fatal("expected a region on src/app.py")
		}
		if err := json.Unmarshal(*phys.Region, &reg); err != nil {
			t.Fatal(err)
		}
		if reg.StartLine != 12 || reg.StartColumn != 5 || reg.EndColumn != 21 {
			t.Errorf("region = %+v (columns are 1-based utf16)", reg)
		}
		if reg.Snippet.Text != `model="gpt-4.1"` {
			t.Errorf("snippet = %q", reg.Snippet.Text)
		}
		if n := res.Locations[0].LogicalLocations; len(n) != 1 || n[0].Name != "chat" {
			t.Errorf("logicalLocations = %+v", n)
		}
		return
	}
	t.Fatal("src/app.py result not found")
}

func TestPartialFingerprintRecipe(t *testing.T) {
	for _, res := range parse(t, render(t, false)).Runs[0].Results {
		uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
		var compID string
		switch uri {
		case "src/app.py", "src/util.py":
			compID = "airom:aaaa111122223333"
		case "models/llama.gguf":
			compID = "airom:bbbb444455556666"
		default:
			t.Fatalf("unexpected uri %q", uri)
		}
		sum := sha256.Sum256([]byte(res.RuleID + "|" + compID + "|" + uri))
		want := hex.EncodeToString(sum[:])
		got := res.PartialFingerprints["airomComponentIdentity/v1"]
		if got != want {
			t.Errorf("fingerprint for %s = %q, want %q", uri, got, want)
		}
		if len(got) != 64 {
			t.Errorf("fingerprint not 64 hex chars: %q", got)
		}
	}
}

func TestResultProperties(t *testing.T) {
	for _, res := range parse(t, render(t, false)).Runs[0].Results {
		p := res.Properties
		if p["airom:componentId"] == nil || p["airom:kind"] == nil {
			t.Errorf("missing identity props: %+v", p)
		}
		// Confidences are JSON numbers (§6.2), not strings.
		if _, ok := p["airom:confidence"].(float64); !ok {
			t.Errorf("airom:confidence not a number: %T", p["airom:confidence"])
		}
		if _, ok := p["airom:occurrence.confidence"].(float64); !ok {
			t.Errorf("airom:occurrence.confidence not a number: %T", p["airom:occurrence.confidence"])
		}
		// pickle.risk only on the local model file's result.
		if res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "models/llama.gguf" {
			if p["airom:pickle.risk"] == nil {
				t.Errorf("expected airom:pickle.risk on the pickle-risk component")
			}
			if p["airom:purl"] != "pkg:generic/llama-3-8b?checksum=sha256:00ff" {
				t.Errorf("airom:purl = %v", p["airom:purl"])
			}
		} else if p["airom:pickle.risk"] != nil {
			t.Errorf("unexpected airom:pickle.risk on %s", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
	}
}

func TestMessageText(t *testing.T) {
	got := map[string]string{}
	for _, res := range parse(t, render(t, false)).Runs[0].Results {
		got[res.Locations[0].PhysicalLocation.ArtifactLocation.URI] = res.Message.Text
	}
	if m := got["src/app.py"]; m != "hosted-llm 'openai/gpt-4.1' detected (confidence 0.9)" {
		t.Errorf("hosted message = %q", m)
	}
	if m := got["models/llama.gguf"]; m != "local-model-file 'llama-3-8b' [q4_k_m] detected (confidence 1)" {
		t.Errorf("local message = %q", m)
	}
}

func TestUnknownsAreNotifications(t *testing.T) {
	run := parse(t, render(t, false)).Runs[0]
	notes := run.Invocations[0].ToolExecutionNotifications
	if len(notes) != 2 {
		t.Fatalf("toolExecutionNotifications = %d, want 2", len(notes))
	}
	// The Unknown paths must not appear as results.
	for _, res := range run.Results {
		if res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "data/weird.bin" {
			t.Error("an Unknown leaked into results")
		}
	}
	// First: has a path + detector; second: pipeline-stage, no path → no locations.
	if notes[0].Message.Text != "truncated GGUF header" || notes[0].Level != "note" {
		t.Errorf("note[0] = %+v", notes[0])
	}
	if notes[0].Properties["airom:detectorId"] != "rules/gguf/header" {
		t.Errorf("note[0] detectorId = %v", notes[0].Properties["airom:detectorId"])
	}
	if len(notes[0].Locations) != 1 || notes[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "data/weird.bin" {
		t.Errorf("note[0] locations = %+v", notes[0].Locations)
	}
	if len(notes[1].Locations) != 0 {
		t.Errorf("note[1] (no path) must omit locations, got %+v", notes[1].Locations)
	}
}

func TestDeterminism(t *testing.T) {
	a := render(t, false)
	b := render(t, false)
	if !bytes.Equal(a, b) {
		t.Fatal("output not byte-identical across encodes")
	}
	// strict mode is also stable.
	if !bytes.Equal(render(t, true), render(t, true)) {
		t.Fatal("strict output not byte-identical across encodes")
	}
}

func TestGolden(t *testing.T) {
	got := render(t, false)
	path := filepath.Join("testdata", "inventory.golden.sarif.json")
	if *update || os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil { //nolint:gosec // golden fixture
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from golden; run: go test ./internal/writer/sarifw/ -update")
	}
}

// TestRemoteRepoOmitsSRCROOT: a remote-URL repo scan must not emit a bogus
// file:///https://… SRCROOT base; its provenance travels via
// versionControlProvenance instead. (Phase 10 review, writers-conformance.)
func TestRemoteRepoOmitsSRCROOT(t *testing.T) {
	inv := sample()
	inv.Source = airom.SourceInfo{
		Kind:   "repo",
		Target: "https://github.com/foo/bar",
		Git:    &airom.GitInfo{Remote: "https://github.com/foo/bar", Commit: "abc123"},
	}
	var buf bytes.Buffer
	if err := sarifw.New(writer.Options{}).Write(&buf, inv); err != nil {
		t.Fatal(err)
	}
	// No file:// URI must appear anywhere for a URL target.
	if bytes.Contains(buf.Bytes(), []byte("file:///https")) {
		t.Fatalf("emitted a malformed file:// SRCROOT for a URL target:\n%s", buf.String())
	}
	run := parse(t, buf.Bytes()).Runs[0]
	if len(run.OriginalURIBaseIDs) != 0 {
		t.Errorf("originalUriBaseIds should be omitted for a remote repo, got %+v", run.OriginalURIBaseIDs)
	}
	if len(run.VersionControlProvenance) != 1 || run.VersionControlProvenance[0].RepositoryURI != "https://github.com/foo/bar" {
		t.Errorf("remote provenance missing: %+v", run.VersionControlProvenance)
	}

	// A LOCAL repo worktree still gets SRCROOT.
	inv.Source = airom.SourceInfo{Kind: "repo", Target: "/home/user/checkout"}
	buf.Reset()
	if err := sarifw.New(writer.Options{}).Write(&buf, inv); err != nil {
		t.Fatal(err)
	}
	if got := parse(t, buf.Bytes()).Runs[0].OriginalURIBaseIDs["SRCROOT"].URI; got != "file:///home/user/checkout/" {
		t.Errorf("local repo SRCROOT = %q, want file:///home/user/checkout/", got)
	}
}
