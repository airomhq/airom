package app

import (
	"context"
	"testing"
)

// testScopedTree: production code naming one model, a test tree naming another.
var testScopedTree = map[string]string{
	"app.py": `from openai import OpenAI
OpenAI().chat.completions.create(model="gpt-4o", messages=[])
`,
	"tests/test_app.py": `from openai import OpenAI
OpenAI().chat.completions.create(model="gpt-4-32k", messages=[])
`,
}

func scanTestScoped(t *testing.T, tweak func(*Config)) map[string]bool {
	t.Helper()
	cfg := &Config{Source: SourceFS, Target: writeTree(t, testScopedTree), Now: eolScanDay}
	if tweak != nil {
		tweak(cfg)
	}
	inv, err := Scan(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, c := range inv.Components {
		got[c.Name] = c.TestOnly
	}
	return got
}

// TestScanMarksTestOnlyComponents: the assembler's verdict has to survive the
// whole pipeline, since every downstream filter keys on it.
func TestScanMarksTestOnlyComponents(t *testing.T) {
	got := scanTestScoped(t, nil)
	if v, ok := got["gpt-4-32k"]; !ok || !v {
		t.Errorf("gpt-4-32k should be test-only (named only under tests/), got %v ok=%v", v, ok)
	}
	if v, ok := got["gpt-4o"]; !ok || v {
		t.Errorf("gpt-4o is production code and must not be test-only, got %v ok=%v", v, ok)
	}
	// Nothing is dropped from the document — the native format is the lossless
	// superset, and hiding is a presentation decision made downstream.
	if len(got) < 2 {
		t.Errorf("the scan must still CONTAIN both components, got %v", got)
	}
}

// TestEOLGateIgnoresTestOnlyByDefault is the finding that made this feature
// urgent: AIROM's own repository carries fixtures naming a retired model, so a
// test-counting gate fails every build over a file that ships to nobody. A gate
// that cries wolf gets deleted from the pipeline.
func TestEOLGateIgnoresTestOnlyByDefault(t *testing.T) {
	target := writeTree(t, testScopedTree)
	run := func(includeTests bool) error {
		p, err := ParsePolicy("eol:retired")
		if err != nil {
			t.Fatal(err)
		}
		cfg := &Config{
			Source: SourceFS, Target: target, Now: eolScanDay,
			Policy: p, IncludeTests: includeTests, ExitCode: 1,
		}
		inv, err := Scan(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		return gate(inv, cfg)
	}
	if err := run(false); err != nil {
		t.Errorf("a retired model reached only from tests must not fail the build: %v", err)
	}
	if err := run(true); err == nil {
		t.Error("--include-tests must let the same finding trip the gate: the user asked to count tests")
	}
}
