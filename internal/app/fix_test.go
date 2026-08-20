package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

// captureStderr redirects the shared stderr sink to a pipe for the duration of
// a test and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := stderr
	stderr = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()

	fn()
	stderr = saved
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// vulnerableInventory is a scan result with one fixable package and one whose
// only sighting is a lockfile.
func vulnerableInventory() *airom.Inventory {
	occ := func(detector, path string, line int, snippet string) airom.Occurrence {
		return airom.Occurrence{
			Location:   airom.Location{Path: path, Line: line},
			DetectorID: detector, Confidence: 0.95, Snippet: snippet,
		}
	}
	return &airom.Inventory{Components: []airom.Component{
		{Kind: airom.KindApplication, Name: ".", Confidence: 1.0},
		{
			Kind: airom.KindFramework, Name: "langchain", Confidence: 0.95,
			Version: airom.KnownString("0.0.310"), PURL: "pkg:pypi/langchain@0.0.310",
			Vulnerabilities: []airom.Vulnerability{{ID: "CVE-1", Severity: airom.VulnHigh, Fixed: "0.2.4"}},
			Evidence: airom.Evidence{Occurrences: []airom.Occurrence{
				occ("manifest/pypi-requirements", "requirements.txt", 1, "langchain==0.0.310"),
			}},
		},
		{
			Kind: airom.KindLibrary, Name: "locked", Confidence: 0.95,
			Version: airom.KnownString("1.0.0"), PURL: "pkg:pypi/locked@1.0.0",
			Vulnerabilities: []airom.Vulnerability{{ID: "CVE-2", Severity: airom.VulnLow, Fixed: "1.1.0"}},
			Evidence: airom.Evidence{Occurrences: []airom.Occurrence{
				occ("manifest/pypi-lock", "poetry.lock", 9, `name = "locked"`),
			}},
		},
	}}
}

// TestRunFixesAppliesAndReports is the --fix-all path end to end: the pin moves,
// the report names the edit, and the finding it could not fix is still stated.
func TestRunFixesAppliesAndReports(t *testing.T) {
	root := t.TempDir()
	req := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(req, []byte("langchain==0.0.310\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "poetry.lock"), []byte("[[package]]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Source: SourceFS, Target: root, CVE: true, FixAll: true}
	out := captureStderr(t, func() {
		if err := runFixes(context.Background(), vulnerableInventory(), cfg); err != nil {
			t.Fatalf("runFixes: %v", err)
		}
	})

	got, _ := os.ReadFile(req)
	if string(got) != "langchain==0.2.4\n" {
		t.Errorf("requirements.txt = %q, want the bumped pin", got)
	}
	for _, want := range []string{
		"updated 1 pin", "requirements.txt:1", "langchain==0.0.310", "langchain==0.2.4",
		"1 package(s) need a manual change", "locked", "lockfile",
		"Re-run the scan",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q\ngot:\n%s", want, out)
		}
	}
}

// TestRunFixesFallsBackWithoutATerminal: --fix on a pipe must not fail the
// scan; it says what the table would have offered and names the flag that
// works without one.
func TestRunFixesFallsBackWithoutATerminal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"),
		[]byte("langchain==0.0.310\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Source: SourceFS, Target: root, CVE: true, Fix: true}
	out := captureStderr(t, func() {
		if err := runFixes(context.Background(), vulnerableInventory(), cfg); err != nil {
			t.Fatalf("runFixes: %v", err)
		}
	})
	if !strings.Contains(out, "--fix-all") || !strings.Contains(out, "needs a terminal") {
		t.Errorf("fallback report =\n%s\nwant it to name the terminal requirement and --fix-all", out)
	}
	got, _ := os.ReadFile(filepath.Join(root, "requirements.txt"))
	if string(got) != "langchain==0.0.310\n" {
		t.Errorf("the fallback path edited the file: %q", got)
	}
}

// TestRunFixesIsOffByDefault. A scanner that rewrites a tree nobody asked it to
// rewrite is not a scanner.
func TestRunFixesIsOffByDefault(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(p, []byte("langchain==0.0.310\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Source: SourceFS, Target: root, CVE: true}
	if out := captureStderr(t, func() {
		if err := runFixes(context.Background(), vulnerableInventory(), cfg); err != nil {
			t.Fatal(err)
		}
	}); out != "" {
		t.Errorf("a scan with neither flag printed a fix report: %q", out)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "langchain==0.0.310\n" {
		t.Errorf("a scan with neither flag edited the file: %q", got)
	}
}

// TestRunFixesRespectsMinConfidence keeps the fix table showing the same
// inventory the emitted AIBOM does.
func TestRunFixesRespectsMinConfidence(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(p, []byte("langchain==0.0.310\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := vulnerableInventory()
	inv.Components[1].Confidence = 0.5

	cfg := &Config{Source: SourceFS, Target: root, CVE: true, FixAll: true, MinConfidence: 0.9}
	captureStderr(t, func() {
		if err := runFixes(context.Background(), inv, cfg); err != nil {
			t.Fatal(err)
		}
	})
	got, _ := os.ReadFile(p)
	if string(got) != "langchain==0.0.310\n" {
		t.Errorf("a component the filter dropped was still fixed: %q", got)
	}
}

// TestValidateFixRejectsImpossibleCombinations: each one fails loudly at config
// time rather than running a scan that then quietly remediates nothing.
func TestValidateFixRejectsImpossibleCombinations(t *testing.T) {
	base := func() *Config {
		c := &Config{Source: SourceFS, Target: ".", CVE: true}
		c.ApplyDefaults()
		return c
	}
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{"both flags", func(c *Config) { c.Fix, c.FixAll = true, true }, "mutually exclusive"},
		{"no cve overlay", func(c *Config) { c.Fix, c.CVE = true, false }, "CVE overlay"},
		{"image scan", func(c *Config) { c.Fix, c.Source = true, SourceImage }, "filesystem scan"},
		{"repo scan", func(c *Config) { c.FixAll, c.Source = true, SourceRepo }, "filesystem scan"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatal("Validate accepted an impossible combination")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}

	// The supported combination still validates.
	c := base()
	c.Fix = true
	if err := c.Validate(); err != nil {
		t.Errorf("--fix on a filesystem scan was rejected: %v", err)
	}
}
