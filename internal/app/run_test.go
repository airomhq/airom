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
