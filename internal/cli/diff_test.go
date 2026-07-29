package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airomhq/airom/internal/app"
	"github.com/airomhq/airom/pkg/airom"
)

// writeAIBOM marshals a minimal native document to dir/name and returns its
// path.
func writeAIBOM(t *testing.T, dir, name string, comps ...airom.Component) string {
	t.Helper()
	root := airom.Component{ID: "airom:0000000000000000", Kind: airom.KindApplication, Name: "app"}
	doc := airom.Inventory{
		SchemaVersion: "1",
		Source:        airom.SourceInfo{Kind: "fs", Target: name},
		Root:          root.ID,
		Components:    append([]airom.Component{root}, comps...),
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func diffFixtures(t *testing.T) (oldPath, newPath string) {
	t.Helper()
	dir := t.TempDir()
	oldPath = writeAIBOM(
		t, dir, "old.json",
		airom.Component{
			ID: "airom:00000000000000aa", Kind: airom.KindFramework, Name: "langchain",
			Version: airom.KnownString("0.2.1"), Confidence: 0.95,
		},
	)
	newPath = writeAIBOM(
		t, dir, "new.json",
		airom.Component{
			ID: "airom:00000000000000aa", Kind: airom.KindFramework, Name: "langchain",
			Version: airom.KnownString("0.3.0"), Confidence: 0.95,
		},
		airom.Component{
			ID: "airom:00000000000000bb", Kind: airom.KindHostedLLM, Name: "gpt-4.1",
			Provider: airom.KnownString("openai"), Confidence: 0.95,
		},
	)
	return oldPath, newPath
}

func TestDiffCommand(t *testing.T) {
	oldPath, newPath := diffFixtures(t)
	out, err := execute(t, "diff", oldPath, newPath)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	for _, want := range []string{"AIBOM Diff", "1 added, 0 removed, 1 changed", "gpt-4.1", "langchain"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestDiffCommandMarkdown(t *testing.T) {
	oldPath, newPath := diffFixtures(t)
	out, err := execute(t, "diff", oldPath, newPath, "--format", "markdown")
	if err != nil {
		t.Fatalf("diff --format markdown: %v", err)
	}
	if !strings.Contains(out, "## AIBOM diff") || !strings.Contains(out, "### Added") {
		t.Errorf("markdown output:\n%s", out)
	}
}

func TestDiffCommandJSON(t *testing.T) {
	oldPath, newPath := diffFixtures(t)
	out, err := execute(t, "diff", oldPath, newPath, "--format", "json")
	if err != nil {
		t.Fatalf("diff --format json: %v", err)
	}
	var doc struct {
		Summary struct{ Added, Changed int } `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json output does not parse: %v\n%s", err, out)
	}
	if doc.Summary.Added != 1 || doc.Summary.Changed != 1 {
		t.Fatalf("summary = %+v", doc.Summary)
	}
}

func TestDiffFailOnMatchesAddedComponent(t *testing.T) {
	oldPath, newPath := diffFixtures(t)
	out, err := execute(t, "diff", oldPath, newPath, "--fail-on", "hosted-llm")
	var pe *app.PolicyExit
	if !errors.As(err, &pe) || pe.Code != 1 {
		t.Fatalf("err = %v, want PolicyExit code 1", err)
	}
	// The report is still emitted before the gate fires.
	if !strings.Contains(out, "gpt-4.1") {
		t.Errorf("gated diff swallowed its report:\n%s", out)
	}
}

func TestDiffFailOnHonorsExitCode(t *testing.T) {
	oldPath, newPath := diffFixtures(t)
	_, err := execute(t, "diff", oldPath, newPath, "--fail-on", "hosted-llm", "--exit-code", "3")
	var pe *app.PolicyExit
	if !errors.As(err, &pe) || pe.Code != 3 {
		t.Fatalf("err = %v, want PolicyExit code 3", err)
	}
}

func TestDiffFailOnRemovalDoesNotTrip(t *testing.T) {
	// vector-db exists only on the old side: a removal must not gate.
	dir := t.TempDir()
	oldPath := writeAIBOM(t, dir, "old.json",
		airom.Component{ID: "airom:00000000000000aa", Kind: airom.KindVectorDB, Name: "chroma", Confidence: 0.9})
	newPath := writeAIBOM(t, dir, "new.json")
	if _, err := execute(t, "diff", oldPath, newPath, "--fail-on", "vector-db"); err != nil {
		t.Fatalf("removal tripped the gate: %v", err)
	}
}

func TestDiffExitCodeAloneFailsOnAnyDelta(t *testing.T) {
	oldPath, newPath := diffFixtures(t)
	_, err := execute(t, "diff", oldPath, newPath, "--exit-code", "1")
	var pe *app.PolicyExit
	if !errors.As(err, &pe) || pe.Code != 1 {
		t.Fatalf("err = %v, want PolicyExit code 1", err)
	}

	// No delta → no gate.
	if _, err := execute(t, "diff", oldPath, oldPath, "--exit-code", "1"); err != nil {
		t.Fatalf("identical documents tripped the gate: %v", err)
	}
}

func TestDiffUsageErrors(t *testing.T) {
	oldPath, newPath := diffFixtures(t)
	cases := [][]string{
		{"diff", oldPath},
		{"diff", oldPath, newPath, "--format", "cyclonedx"},
		{"diff", oldPath, newPath, "-o", "table"},
		{"diff", oldPath, newPath, "--fail-on", "compliance:gap"},
		{"diff", oldPath, newPath, "--fail-on", "no-such-term"},
	}
	for _, args := range cases {
		_, err := execute(t, args...)
		var uerr *app.UsageError
		if !errors.As(err, &uerr) {
			t.Errorf("%v: err = %v, want UsageError", args, err)
		}
	}
}

func TestDiffMissingFileIsFatalNotUsage(t *testing.T) {
	dir := t.TempDir()
	oldPath := writeAIBOM(t, dir, "old.json")
	_, err := execute(t, "diff", oldPath, filepath.Join(dir, "absent.json"))
	if err == nil {
		t.Fatal("missing file accepted")
	}
	var uerr *app.UsageError
	var pe *app.PolicyExit
	if errors.As(err, &uerr) || errors.As(err, &pe) {
		t.Fatalf("err = %v, want a plain fatal error", err)
	}
}

func TestDiffIncludeTests(t *testing.T) {
	dir := t.TempDir()
	oldPath := writeAIBOM(t, dir, "old.json")
	newPath := writeAIBOM(t, dir, "new.json",
		airom.Component{
			ID: "airom:00000000000000aa", Kind: airom.KindHostedLLM, Name: "gpt-4.1",
			Confidence: 0.9, TestOnly: true,
		})

	out, err := execute(t, "diff", oldPath, newPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "test-scoped component(s) skipped") {
		t.Errorf("skipped test-scoped components not surfaced:\n%s", out)
	}

	out, err = execute(t, "diff", oldPath, newPath, "--include-tests")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "gpt-4.1") {
		t.Errorf("--include-tests did not count the fixture component:\n%s", out)
	}
}

// writeAIBOMWithTool is writeAIBOM plus the tooling provenance a real scan
// stamps, so a test can make two documents disagree about how they were made.
func writeAIBOMWithTool(t *testing.T, dir, name, rulesHash string, comps ...airom.Component) string {
	t.Helper()
	path := writeAIBOM(t, dir, name, comps...)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc airom.Inventory
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Tool = airom.ToolInfo{Name: "airom", Version: "0.2.2", RulesVersion: "builtin", RulesHash: rulesHash}
	b, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestDiffRefusesToGateAcrossToolingDrift is the reason the guard exists.
// Two scans of unchanged code, produced by different rulesets, disagree — and
// gating that disagreement fails a build for AI nobody wrote. Refusing (exit
// 2, "cannot answer") is the only honest verdict: skipping the gate would be a
// false green, running it a false red.
func TestDiffRefusesToGateAcrossToolingDrift(t *testing.T) {
	dir := t.TempDir()
	oldPath := writeAIBOMWithTool(t, dir, "old.json", "aaaaaaaaaaaaaaaa")
	newPath := writeAIBOMWithTool(t, dir, "new.json", "bbbbbbbbbbbbbbbb",
		airom.Component{ID: "airom:00000000000000cc", Kind: airom.KindHostedLLM, Name: "gpt-4.1", Confidence: 0.9})

	out, err := execute(t, "diff", oldPath, newPath, "--fail-on", "hosted-llm")
	var ue *app.UsageError
	if !errors.As(err, &ue) {
		t.Fatalf("err = %v, want a UsageError (exit 2) — not a pass and not a policy failure", err)
	}
	if !strings.Contains(err.Error(), "ruleset hash") {
		t.Errorf("the error must name what drifted, got: %v", err)
	}
	// The report still prints: the reader gets the delta plus the reason it is
	// not being gated.
	if !strings.Contains(out, "Not comparable") {
		t.Errorf("the diff must still be reported under drift:\n%s", out)
	}
}

// TestDiffReportsDriftWithoutAGate: no --fail-on means nothing to refuse, so
// the diff succeeds — carrying the caveat rather than withholding the report.
func TestDiffReportsDriftWithoutAGate(t *testing.T) {
	dir := t.TempDir()
	oldPath := writeAIBOMWithTool(t, dir, "old.json", "aaaaaaaaaaaaaaaa")
	newPath := writeAIBOMWithTool(t, dir, "new.json", "bbbbbbbbbbbbbbbb")

	out, err := execute(t, "diff", oldPath, newPath)
	if err != nil {
		t.Fatalf("an ungated diff must succeed under drift: %v", err)
	}
	if !strings.Contains(out, "Not comparable") {
		t.Errorf("the caveat must still be shown:\n%s", out)
	}
}

// TestDiffSameToolingGatesNormally: the guard must not disturb the normal
// case, where base and head are scanned in one CI run by one binary.
func TestDiffSameToolingGatesNormally(t *testing.T) {
	dir := t.TempDir()
	oldPath := writeAIBOMWithTool(t, dir, "old.json", "aaaaaaaaaaaaaaaa")
	newPath := writeAIBOMWithTool(t, dir, "new.json", "aaaaaaaaaaaaaaaa",
		airom.Component{ID: "airom:00000000000000cc", Kind: airom.KindHostedLLM, Name: "gpt-4.1", Confidence: 0.9})

	out, err := execute(t, "diff", oldPath, newPath, "--fail-on", "hosted-llm")
	var pe *app.PolicyExit
	if !errors.As(err, &pe) {
		t.Fatalf("identical tooling must gate normally, got %v", err)
	}
	if strings.Contains(out, "Not comparable") {
		t.Error("no drift, so no caveat")
	}
}
