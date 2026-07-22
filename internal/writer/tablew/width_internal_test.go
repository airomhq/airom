package tablew

import (
	"bytes"
	"strings"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestDispWidth(t *testing.T) {
	cases := []struct {
		s    string
		want int
	}{
		{"", 0}, {"abc", 3}, {"日本語", 6}, {"a日b", 4}, {"🚀", 2},
	}
	for _, c := range cases {
		if got := dispWidth(c.s); got != c.want {
			t.Errorf("dispWidth(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

// TestVulnTableMergesPerPackageColumns checks the Trivy-style vertical merge:
// two CVEs on the same package share one LIBRARY and INSTALLED cell (each value
// appears once), while a differing FIXED version is NOT merged. Every rendered
// line still has identical display width (the box stays rectangular).
func TestVulnTableMergesPerPackageColumns(t *testing.T) {
	inv := &airom.Inventory{
		Source: airom.SourceInfo{Target: "/x"},
		Components: []airom.Component{{
			ID: "a", Kind: airom.KindFramework, Name: "torch", Version: airom.KnownString("2.1.0"), Confidence: 0.9,
			Vulnerabilities: []airom.Vulnerability{
				{ID: "CVE-2025-1", Severity: airom.VulnHigh, Score: 7.5, Fixed: "2.7.1", Summary: "A.", Source: "osv.dev", URL: "u1"},
				{ID: "CVE-2025-2", Severity: airom.VulnHigh, Score: 7.5, Fixed: "2.9.0", Summary: "B.", Source: "osv.dev", URL: "u2"},
			},
			Evidence: airom.Evidence{Occurrences: []airom.Occurrence{{Location: airom.Location{Path: "requirements.txt", Line: 1}}}},
		}},
	}
	var buf bytes.Buffer
	if err := (Writer{}).Write(&buf, inv); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	body := out[strings.Index(out, "Vulnerabilities ("):]

	// LIBRARY "torch" and INSTALLED "2.1.0" are per-package: they merge, so each
	// appears exactly once in the detail table.
	if n := strings.Count(body, "torch"); n != 1 {
		t.Errorf("LIBRARY not merged: %q appears %d times, want 1\n%s", "torch", n, body)
	}
	if n := strings.Count(body, "2.1.0"); n != 1 {
		t.Errorf("INSTALLED not merged: %q appears %d times, want 1\n%s", "2.1.0", n, body)
	}
	// The two distinct fixed versions are both present (FIXED not over-merged).
	if !strings.Contains(body, "2.7.1") || !strings.Contains(body, "2.9.0") {
		t.Errorf("both fixed versions should show:\n%s", body)
	}
	// Rectangular: every border/row line of the detail table has equal width.
	want := 0
	for _, l := range strings.Split(body, "\n") {
		r := []rune(l)
		if len(r) == 0 || (r[0] != '┌' && r[0] != '├' && r[0] != '│' && r[0] != '└') {
			continue
		}
		if wdt := dispWidth(l); want == 0 {
			want = wdt
		} else if wdt != want {
			t.Errorf("merged box line width = %d, want %d (not rectangular):\n%q", wdt, want, l)
		}
	}
}

// TestVulnTableWideGlyphRectangular guards the fix for wide (CJK/emoji) advisory
// titles: every border/row line of the per-CVE detail table must have identical
// display width, or the box stops being rectangular in a terminal.
func TestVulnTableWideGlyphRectangular(t *testing.T) {
	inv := &airom.Inventory{
		Source: airom.SourceInfo{Target: "/x"},
		Components: []airom.Component{{
			ID: "a", Kind: airom.KindFramework, Name: "torch", Version: airom.KnownString("2.1.0"), Confidence: 0.9,
			Vulnerabilities: []airom.Vulnerability{{
				ID: "CVE-2024-1", Severity: airom.VulnCritical, Score: 9.8, Fixed: "2.2.0",
				Summary: "远程代码执行漏洞在模型加载器中触发任意命令执行", Source: "osv.dev",
				URL: "https://osv.dev/vulnerability/CVE-2024-1",
			}},
			Evidence: airom.Evidence{Occurrences: []airom.Occurrence{{Location: airom.Location{Path: "requirements.txt", Line: 1}}}},
		}},
	}
	var buf bytes.Buffer
	if err := (Writer{}).Write(&buf, inv); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(buf.String(), "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "Vulnerabilities (") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("no vuln detail table in:\n%s", buf.String())
	}
	want := 0
	for _, l := range lines[start:] {
		if l == "" {
			break
		}
		r := []rune(l)
		if len(r) == 0 || (r[0] != '┌' && r[0] != '├' && r[0] != '│' && r[0] != '└') {
			continue
		}
		if w := dispWidth(l); want == 0 {
			want = w
		} else if w != want {
			t.Errorf("vuln box line display-width = %d, want %d (box not rectangular):\n%q", w, want, l)
		}
	}
}
