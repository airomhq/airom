package fixui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airomhq/airom/internal/fix"
	"github.com/airomhq/airom/internal/tui"
	"github.com/airomhq/airom/pkg/airom"
)

// plain is a styling-disabled palette, so tests assert on text rather than on
// escape sequences.
func plain() tui.Palette { return tui.NewPalette(nil) }

func vuln(id string, sev airom.VulnSeverity) fix.Vuln {
	return fix.Vuln{ID: id, Severity: sev}
}

func demo() []fix.Target {
	return []fix.Target{
		{
			Package: "langchain", Ecosystem: "pypi", Current: "0.0.310", Fixed: "0.2.4",
			Severity: airom.VulnCritical, Major: true, Fixable: true,
			Sites: []fix.Site{{File: "requirements.txt", Line: 1, Snippet: "langchain==0.0.310"}},
			Vulns: []fix.Vuln{vuln("CVE-A", airom.VulnCritical), vuln("CVE-B", airom.VulnLow)},
		},
		{
			Package: "transformers", Ecosystem: "pypi", Current: "4.30.0", Fixed: "4.53.0",
			Severity: airom.VulnMedium, Fixable: true,
			Sites: []fix.Site{{File: "requirements.txt", Line: 2, Snippet: "transformers==4.30.0"}},
			Vulns: []fix.Vuln{vuln("CVE-C", airom.VulnMedium)},
		},
		{
			Package: "locked", Ecosystem: "pypi", Current: "1.0.0", Fixed: "1.1.0",
			Severity: airom.VulnHigh, Reason: "only seen in a lockfile",
			Vulns: []fix.Vuln{vuln("CVE-D", airom.VulnHigh)},
		},
	}
}

// TestRowsMergePerPackage: a package with several advisories states its name,
// its version, and its button once — the same vertical merge the printed table
// does, so the two views read alike.
func TestRowsMergePerPackage(t *testing.T) {
	m := newModel(t.TempDir(), demo(), plain())
	if len(m.rows) != 4 {
		t.Fatalf("rows = %d, want one per advisory (4)", len(m.rows))
	}
	want := []struct {
		target int
		first  bool
	}{{0, true}, {0, false}, {1, true}, {2, true}}
	for i, w := range want {
		if m.rows[i].target != w.target || m.rows[i].first != w.first {
			t.Errorf("row %d = target %d first=%v, want target %d first=%v",
				i, m.rows[i].target, m.rows[i].first, w.target, w.first)
		}
	}
}

// TestClickOnActionApplies is the feature in one test: a click landing in the
// ACTION column rewrites that package's pin, and a click elsewhere only moves
// the cursor.
func TestClickOnActionApplies(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"),
		[]byte("langchain==0.0.310\ntransformers==4.30.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := newModel(root, demo(), plain())
	m.layout(120, 40)

	// A click inside the table but left of ACTION selects without acting.
	m.handle(event{Kind: evtClick, Col: 2, Row: m.bodyTop + 2})
	if m.cursor != 2 {
		t.Errorf("cursor = %d, want the clicked row 2", m.cursor)
	}
	if m.state[1].applied {
		t.Fatal("a click outside the ACTION column applied a fix")
	}

	// A click on the button applies.
	m.handle(event{Kind: evtClick, Col: m.actionX0 + 1, Row: m.bodyTop + 2})
	if !m.state[1].applied {
		t.Fatalf("clicking [ Fix ] did not apply; status = %q", m.status)
	}
	got, _ := os.ReadFile(filepath.Join(root, "requirements.txt"))
	if want := "langchain==0.0.310\ntransformers==4.53.0\n"; string(got) != want {
		t.Errorf("file =\n%q\nwant\n%q", got, want)
	}
	if m.actionLabel(1) != "✔ fixed" {
		t.Errorf("ACTION cell = %q, want the fixed marker", m.actionLabel(1))
	}
	if len(m.outcome.Applied) != 1 || m.outcome.Fixed[0] != "transformers" {
		t.Errorf("outcome = %+v, want one applied fix for transformers", m.outcome)
	}
}

// TestClickOnContinuationRowApplies: the button is drawn once per package, but
// the whole ACTION column is a plausible place to aim.
func TestClickOnContinuationRowApplies(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"),
		[]byte("langchain==0.0.310\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := newModel(root, demo(), plain())
	m.layout(120, 40)
	m.handle(event{Kind: evtClick, Col: m.actionX0 + 1, Row: m.bodyTop + 1}) // langchain's 2nd advisory
	if !m.state[0].applied {
		t.Errorf("a click on a continuation row did not fix the package; status = %q", m.status)
	}
}

// TestClickOutsideTheBodyIsIgnored keeps a click on the header or the footer
// from selecting or applying anything.
func TestClickOutsideTheBodyIsIgnored(t *testing.T) {
	m := newModel(t.TempDir(), demo(), plain())
	m.layout(120, 40)
	for _, row := range []int{0, m.bodyTop - 1, m.bodyTop + len(m.rows)} {
		m.cursor = 0
		m.handle(event{Kind: evtClick, Col: m.actionX0 + 1, Row: row})
		if m.state[0].applied {
			t.Fatalf("a click at row %d applied a fix", row)
		}
	}
}

// TestUnfixableTargetRefusesWithItsReason: pressing Fix on a lockfile-only
// finding must say why, not fail silently.
func TestUnfixableTargetRefusesWithItsReason(t *testing.T) {
	m := newModel(t.TempDir(), demo(), plain())
	m.layout(120, 40)
	m.cursor = 3 // the "locked" package
	m.handle(event{Kind: evtActivate})
	if m.statusK != statusBad || !strings.Contains(m.status, "lockfile") {
		t.Errorf("status = %q (kind %v), want the refusal reason", m.status, m.statusK)
	}
	if m.actionLabel(2) != "— manual" {
		t.Errorf("ACTION cell = %q, want the manual marker", m.actionLabel(2))
	}
}

// TestFixAllSkipsWhatItCannotFix and reports the tally, not the last message.
func TestFixAllSkipsWhatItCannotFix(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"),
		[]byte("langchain==0.0.310\ntransformers==4.30.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := newModel(root, demo(), plain())
	m.layout(120, 40)
	m.handle(event{Kind: evtFixAll})

	if !m.state[0].applied || !m.state[1].applied {
		t.Error("fix-all left a fixable package untouched")
	}
	if m.state[2].applied {
		t.Error("fix-all rewrote something it had no manifest for")
	}
	got, _ := os.ReadFile(filepath.Join(root, "requirements.txt"))
	if want := "langchain==0.2.4\ntransformers==4.53.0\n"; string(got) != want {
		t.Errorf("file =\n%q\nwant\n%q", got, want)
	}
	if !strings.Contains(m.status, "fixed 2") || !strings.Contains(m.status, "manual") {
		t.Errorf("status = %q, want both the count fixed and the count needing a human", m.status)
	}
	// A second fix-all has nothing left to do and must not re-bump.
	m.handle(event{Kind: evtFixAll})
	after, _ := os.ReadFile(filepath.Join(root, "requirements.txt"))
	if string(after) != string(got) {
		t.Errorf("a second fix-all changed the file again: %q", after)
	}
}

// TestRenderShowsThePlan checks the frame carries what the user has to see
// before pressing anything: the pin, the target version, the major-bump mark,
// and the edit the button would make.
func TestRenderShowsThePlan(t *testing.T) {
	m := newModel("/scan/root", demo(), plain())
	m.layout(120, 40)
	out := m.render(120, 40)
	for _, want := range []string{
		"PACKAGE", "VULNERABILITY", "SEVERITY", "INSTALLED", "FIX TO", "ACTION",
		"langchain", "0.0.310", "0.2.4 (major)", "[ Fix ]",
		"transformers", "4.53.0",
		"— manual",                               // the lockfile-only finding
		"requirements.txt:1  langchain==0.0.310", // the detail pane's edit preview
		"major bump",
		"a fix all", "q quit",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("frame is missing %q", want)
		}
	}
}

// TestScrolledGroupKeepsItsHeader: a package with more advisories than the
// screen holds scrolls its own name and button off the top. The first visible
// row has to redraw them, or the user gets a screenful of CVEs belonging to
// nothing, with nothing to press.
func TestScrolledGroupKeepsItsHeader(t *testing.T) {
	tgs := demo()
	for i := range 6 {
		tgs[0].Vulns = append(tgs[0].Vulns, vuln(fmt.Sprintf("CVE-X%d", i), airom.VulnMedium))
	}
	m := newModel(t.TempDir(), tgs, plain())
	m.layout(120, 14) // bodyRows == 3, so rows 1..3 are all langchain continuations
	m.top = 2
	row := m.bodyRow(2)
	if !strings.Contains(row, "langchain") || !strings.Contains(row, "[ Fix ]") {
		t.Errorf("first visible row lost its package header and button:\n%s", row)
	}
	// The rows below it still merge.
	if strings.Contains(m.bodyRow(3), "langchain") {
		t.Errorf("a continuation row repeated the package name:\n%s", m.bodyRow(3))
	}
}

// TestFrameNeverOverflows: a wrapped row breaks the row-to-click mapping, so no
// line may exceed the terminal at any width the table agrees to draw in. The
// long root path is here to catch the header, which is the line most likely to
// run over.
func TestFrameNeverOverflows(t *testing.T) {
	for _, w := range []int{MinWidth, 50, 60, 80, 100, 200} {
		m := newModel("/scan/root/a/very/deep/path/that/keeps/going/and/going", demo(), plain())
		m.layout(w, 40)
		for _, line := range strings.Split(m.render(w, 40), "\r\n") {
			if n := len([]rune(line)); n > w {
				t.Errorf("width %d: a line is %d runes wide: %q", w, n, line)
			}
		}
	}
}

// TestFrameFitsTheTerminal is the guard on the arithmetic that decides where a
// row lands on screen.
//
// bodyRows is derived from the count of fixed lines render() emits. If the two
// ever disagree the frame overflows, the alternate screen scrolls by the
// difference, and bodyTop no longer describes where the body starts — the top
// row stops responding to clicks and every other click applies the row above the
// one that was clicked. It is invisible in a screenshot and total in effect, so
// it is asserted by counting lines rather than by eye.
func TestFrameFitsTheTerminal(t *testing.T) {
	for _, extra := range []int{0, 1, 6, 40} { // plans shorter and far taller than the screen
		tgs := demo()
		for i := range extra {
			tgs[0].Vulns = append(tgs[0].Vulns, vuln(fmt.Sprintf("CVE-X%d", i), airom.VulnMedium))
		}
		for _, h := range []int{MinHeight, MinHeight + 1, 24, 30, 40, 50} {
			m := newModel("/scan/root", tgs, plain())
			m.layout(120, h)
			got := len(strings.Split(m.render(120, h), "\r\n"))
			if got > h {
				t.Errorf("plan of %d rows at h=%d: frame is %d lines, terminal has %d (bodyRows=%d)",
					len(m.rows), h, got, h, m.bodyRows)
			}
			// The body must also start where the click handler believes it does.
			if m.bodyTop != chromeAbove {
				t.Errorf("bodyTop = %d, want %d", m.bodyTop, chromeAbove)
			}
		}
	}
}

// TestTooSmallRefusesTheTable rather than drawing one whose clicks would land on
// the wrong package — in either dimension.
func TestTooSmallRefusesTheTable(t *testing.T) {
	type size struct{ w, h int }
	for _, sz := range []size{{20, 40}, {30, 40}, {MinWidth - 1, 40}, {120, MinHeight - 1}, {120, 4}} {
		w, h := sz.w, sz.h
		m := newModel("/scan/root", demo(), plain())
		m.layout(w, h)
		out := m.render(w, h)
		if n := len(strings.Split(out, "\r\n")); n > h {
			t.Errorf("%dx%d: the notice is %d lines", w, h, n)
		}
		if strings.Contains(out, "┌") {
			t.Errorf("%dx%d: drew a table that cannot fit", w, h)
		}
		if h > 5 && !strings.Contains(out, "--fix-all") {
			t.Errorf("%dx%d: did not name the way out:\n%s", w, h, out)
		}
		for _, line := range strings.Split(out, "\r\n") {
			if n := tui.DispWidth(line); n > w {
				t.Errorf("%dx%d: a line is %d cells wide: %q", w, h, n, line)
			}
		}
	}
}

// TestWidthIsMeasuredInCells, not runes: a CJK scan root or an emoji in a
// package name is two cells per rune, and a row measured short wraps — moving
// every row below it away from where a click is resolved.
func TestWidthIsMeasuredInCells(t *testing.T) {
	tgs := demo()
	tgs[0].Package = "日本語パッケージ"
	for _, w := range []int{MinWidth, 60, 80, 120} {
		m := newModel("/スキャン/ルート/very/deep/path", tgs, plain())
		m.layout(w, 40)
		for _, line := range strings.Split(m.render(w, 40), "\r\n") {
			if n := tui.DispWidth(line); n > w {
				t.Errorf("width %d: a line is %d cells wide: %q", w, n, line)
			}
		}
	}
}

// TestReportIsOrderedBySeverity — the fallback views are where ordering matters
// most, because they are what a user gets when they cannot see the table.
func TestReportIsOrderedBySeverity(t *testing.T) {
	out := Report(demo())
	crit := strings.Index(out, "langchain 0.0.310")  // critical
	high := strings.Index(out, "locked 1.0.0")       // high
	med := strings.Index(out, "transformers 4.30.0") // medium
	if crit < 0 || high < 0 || med < 0 {
		t.Fatalf("report is missing a target:\n%s", out)
	}
	if crit > high || high > med {
		t.Errorf("report is not most-severe-first:\n%s", out)
	}
}

// TestScrollingKeepsTheCursorVisible on a terminal too short for the plan.
func TestScrollingKeepsTheCursorVisible(t *testing.T) {
	m := newModel(t.TempDir(), demo(), plain())
	const h = MinHeight + 1 // room for exactly two body rows
	m.layout(120, h)
	if m.bodyRows != 2 {
		t.Fatalf("bodyRows = %d, want 2", m.bodyRows)
	}
	m.handle(event{Kind: evtEnd})
	m.layout(120, h)
	if m.cursor < m.top || m.cursor >= m.top+m.bodyRows {
		t.Errorf("cursor %d is outside the visible window [%d,%d)", m.cursor, m.top, m.top+m.bodyRows)
	}
	m.handle(event{Kind: evtHome})
	m.layout(120, h)
	if m.top != 0 || m.cursor != 0 {
		t.Errorf("home left top=%d cursor=%d, want 0/0", m.top, m.cursor)
	}
}

// TestCursorStaysInRange under keys that would run off either end.
func TestCursorStaysInRange(t *testing.T) {
	m := newModel(t.TempDir(), demo(), plain())
	m.layout(120, 40)
	for range 20 {
		m.handle(event{Kind: evtDown})
	}
	if m.cursor != len(m.rows)-1 {
		t.Errorf("cursor = %d, want the last row %d", m.cursor, len(m.rows)-1)
	}
	for range 20 {
		m.handle(event{Kind: evtUp})
	}
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want the first row", m.cursor)
	}
}

// TestReportNamesEveryTarget: the non-interactive fallback has to say what the
// table would have offered, including what it could not fix.
func TestReportNamesEveryTarget(t *testing.T) {
	out := Report(demo())
	for _, want := range []string{
		"langchain 0.0.310 -> 0.2.4 [major bump]",
		"transformers 4.30.0 -> 4.53.0",
		"locked 1.0.0: no automatic fix (only seen in a lockfile)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q\ngot:\n%s", want, out)
		}
	}
}
