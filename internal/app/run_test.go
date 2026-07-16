package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRunFSEndToEnd(t *testing.T) {
	root := writeTree(t, map[string]string{
		"app.py":            "import openai\n",
		"web/index.ts":      "const x = 1\n",
		".gitignore":        "*.log\n",
		"debug.log":         "ignored\n",
		"node_modules/x.js": "skipped\n",
	})

	var buf bytes.Buffer
	orig := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = orig })

	cfg := &Config{Source: SourceFS, Target: root}
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "files walked:  3") { // app.py, web/index.ts, .gitignore
		t.Errorf("summary:\n%s", out)
	}
	if !strings.Contains(out, "components:    0") {
		t.Errorf("summary must state honestly that no detectors ran:\n%s", out)
	}
}

func TestRunNonFSSourcesNotWired(t *testing.T) {
	for _, src := range []SourceKind{SourceRepo, SourceImage, SourceK8s} {
		cfg := &Config{Source: src, Target: "x"}
		err := Run(context.Background(), cfg)
		if !errors.Is(err, ErrEngineNotWired) {
			t.Errorf("%s: err = %v, want ErrEngineNotWired", src, err)
		}
	}
}

func TestRunFSBadTargetIsUsageError(t *testing.T) {
	cfg := &Config{Source: SourceFS, Target: filepath.Join(t.TempDir(), "missing")}
	err := Run(context.Background(), cfg)
	var uerr *UsageError
	if !errors.As(err, &uerr) {
		t.Errorf("err = %v, want UsageError (source acquisition failure)", err)
	}
}

func TestRunCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &Config{Source: SourceFS, Target: t.TempDir()}
	if err := Run(ctx, cfg); err == nil {
		t.Error("want error for pre-canceled context")
	}
}

// TestRunFSWithRulesOverlayEndToEnd is the Phase-5 acceptance test: a user
// rule pack (--rules overlay) drives the full framework — walk → classify →
// dispatch → rule engine → assembly — with zero built-in detectors.
func TestRunFSWithRulesOverlayEndToEnd(t *testing.T) {
	root := writeTree(t, map[string]string{
		"app.py":  "import openai\n\nresp = client.chat.completions.create(\n    model=\"gpt-4.1\",\n    temperature=0.2,\n)\n",
		"web.ts":  "const model = \"gpt-4.1\";\n",
		"note.md": "gpt-4.1 mentioned in prose must not match\n",
	})
	pack := filepath.Join(t.TempDir(), "openai.yaml")
	yaml := `pack: openai
version: 1
rules:
  - id: openai/model-literal
    kind: hosted-llm
    provider: openai
    languages: [python, typescript]
    keywords: ["gpt-"]
    pattern: 'model\s*[:=]\s*["''](?P<model>gpt-[\w.\-]+)["'']'
    claim: { name: "${model}" }
    confidence: 0.85
`
	if err := os.WriteFile(pack, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	orig := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = orig })

	cfg := &Config{Source: SourceFS, Target: root, RulePaths: []string{pack}}
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "components:    1") {
		t.Errorf("want exactly one component (two sightings, one identity):\n%s", out)
	}
	if !strings.Contains(out, "hosted-llm") || !strings.Contains(out, "gpt-4.1") {
		t.Errorf("summary missing the detected model:\n%s", out)
	}
	if !strings.Contains(out, "2 occurrences") {
		t.Errorf("want 2 occurrences (py + ts merged by identity):\n%s", out)
	}
}

// TestDetectorsView: the capability view resolves the catalog with a rules
// overlay.
func TestDetectorsView(t *testing.T) {
	pack := filepath.Join(t.TempDir(), "p.yaml")
	yaml := `pack: p
version: 1
rules:
  - id: p/r
    kind: hosted-llm
    keywords: ["kw"]
    pattern: 'kw(?P<model>\w+)'
    claim: { name: "${model}" }
    confidence: 0.5
`
	if err := os.WriteFile(pack, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	infos, err := Detectors(&Config{Source: SourceFS, Target: ".", RulePaths: []string{pack}})
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].ID != "ruleengine" || infos[0].RuleCount != 1 {
		t.Errorf("infos = %+v, want the ruleengine with 1 rule", infos)
	}
}
