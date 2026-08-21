// Package fixui is the interactive CVE table: the advisories a scan found, one
// row per finding, with a Fix action per package that rewrites the manifest pin
// in place.
//
// It obeys the same two rules as internal/tui, for the same reasons. Nothing is
// ever written to stdout — the AIBOM is there and invariant P7 requires it to
// stay byte-identical — and without a terminal the table does not render at
// all; the caller falls back to a plain report. The UI is hand-rolled ANSI over
// a raw tty, matching internal/tui's no-third-party-widget-toolkit posture.
package fixui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/airomhq/airom/internal/fix"
	"github.com/airomhq/airom/internal/tui"
)

// ErrNoTTY reports that there is no terminal to draw the table on, so the
// caller can fall back to the non-interactive report instead of failing.
var ErrNoTTY = errNoTTY

// Outcome is what the session did, for the summary the caller prints once the
// alternate screen is gone and the scroll-back is visible again.
type Outcome struct {
	Applied []fix.Result // successful rewrites, in the order they were made
	Fixed   []string     // package names, one per applied fix
	Failed  int          // fixes attempted that returned an error
}

// Run takes over the terminal, draws the advisory table for targets, and
// applies the fixes the user asks for. root is the scan root every target path
// is relative to.
//
// It returns when the user quits. ErrNoTTY (and only ErrNoTTY) means the table
// never opened.
func Run(root string, targets []fix.Target) (Outcome, error) {
	if len(targets) == 0 {
		return Outcome{}, nil
	}
	s, err := openScreen()
	if err != nil {
		return Outcome{}, err
	}
	defer s.close()

	m := newModel(root, targets, tui.NewPalette(s.in))
	r := newReader(s.in)
	for {
		w, h := s.size()
		m.layout(w, h)
		s.paint(m.render(w, h))

		ev := r.next()
		if ev.Kind == evtQuit {
			return m.outcome, nil
		}
		m.handle(ev)
	}
}

// rowState is the per-package outcome of this session: untouched, fixed, or
// refused with a reason.
type rowState struct {
	applied bool
	result  fix.Result
	err     string
}

// row is one visible line of the table: a (package, advisory) pair. Packages
// with several advisories occupy several rows, and only the first of them draws
// the per-package columns — the same vertical merge the printed table does, so
// the two views read alike.
type row struct {
	target int
	vuln   int
	first  bool // first row of this package's group
}

type model struct {
	root    string
	targets []fix.Target
	state   []rowState
	pal     tui.Palette

	rows   []row
	cursor int
	top    int // first visible row index

	// layout, recomputed each frame from the terminal size
	widths   [colCount]int
	shown    [colCount]bool
	bodyTop  int // screen row of the first table body line
	bodyRows int // how many body lines fit
	actionX0 int // screen column range of the ACTION cell
	actionX1 int

	status  string
	statusK statusKind
	outcome Outcome
}

type statusKind int

const (
	statusNone statusKind = iota
	statusGood
	statusBad
)

// The table's columns, in order.
const (
	colPackage = iota
	colVuln
	colSeverity
	colInstalled
	colFixTo
	colAction
	colCount
)

var headers = [colCount]string{"PACKAGE", "VULNERABILITY", "SEVERITY", "INSTALLED", "FIX TO", "ACTION"}

// minWidths floor each column at the point where its content is still worth
// reading. Shrinking stops here first, and only a terminal narrower than the
// floors allow pushes past it.
var minWidths = [colCount]int{10, 12, 8, 9, 8, 8}

// hardMin is the absolute floor for the elastic columns once dropping columns
// has not been enough. Below eight runes a package name and a CVE id are both
// unrecognizable.
const hardMin = 8

// The frame's fixed lines, above and below the table body. render() must emit
// exactly this many, because bodyRows is derived from them: one line of drift
// scrolls the alternate screen, which moves every row one line off the position
// the click handler computes from bodyTop — so the top row stops responding and
// every other click applies the row above the one that was clicked.
//
// TestFrameFitsTheTerminal holds the two in agreement.
const (
	chromeAbove = 6 // title, counts, blank, top border, header row, separator
	chromeBelow = 6 // bottom border, scroll note, detail (2), status, footer
)

// MinHeight is the shortest terminal the table can be drawn in: the fixed lines
// plus a single row of body.
const MinHeight = chromeAbove + chromeBelow + 1

// MinWidth is the narrowest terminal the table can be drawn in: the margin, the
// four columns that never drop, each at hardMin, and their borders.
//
// Narrower than this the box would wrap, and a wrapped row breaks the one thing
// the table exists for — a click landing on the right package. So below
// MinWidth the table refuses to draw rather than drawing a lie.
const MinWidth = margin + 1 + 4*(hardMin+3)

// dropOrder lists the columns a too-narrow terminal may lose, least costly
// first. PACKAGE, VULNERABILITY, FIX TO, and ACTION are never dropped: between
// them they say which finding a row is, what would change, and how to change
// it, which is the whole table. Severity and the installed version are
// recoverable from the detail pane below it.
var dropOrder = []int{colSeverity, colInstalled}

// newModel builds the table state for a plan. Separate from Run so the layout,
// hit-testing, and apply logic are testable without a terminal to open.
func newModel(root string, targets []fix.Target, pal tui.Palette) *model {
	m := &model{
		root:    root,
		targets: targets,
		pal:     pal,
		state:   make([]rowState, len(targets)),
	}
	m.buildRows()
	return m
}

func (m *model) buildRows() {
	m.rows = nil
	for i, t := range m.targets {
		if len(t.Vulns) == 0 {
			m.rows = append(m.rows, row{target: i, vuln: -1, first: true})
			continue
		}
		for j := range t.Vulns {
			m.rows = append(m.rows, row{target: i, vuln: j, first: j == 0})
		}
	}
}

// margin is the blank column the whole frame is indented by.
const margin = 1

// layout fits the table to the terminal: size every column to its content,
// shrink the elastic ones, and — only when that is not enough — drop the
// columns whose information the detail pane repeats anyway.
func (m *model) layout(w, h int) {
	for c := range m.widths {
		m.widths[c] = runeLen(headers[c])
		m.shown[c] = true
	}
	for _, r := range m.rows {
		t := m.targets[r.target]
		m.grow(colPackage, t.Package)
		m.grow(colInstalled, t.Current)
		m.grow(colFixTo, fixToLabel(t))
		m.grow(colAction, m.actionLabel(r.target))
		if r.vuln >= 0 {
			m.grow(colVuln, t.Vulns[r.vuln].ID)
			m.grow(colSeverity, string(t.Vulns[r.vuln].Severity))
		}
	}

	m.shrink(colVuln, colPackage, minWidths, w)
	for _, c := range dropOrder {
		if m.tableWidth() <= w {
			break
		}
		m.shown[c] = false
	}
	// Past the floors now: a narrower terminal gets truncated names rather than
	// a table sheared off at the right edge. FIX TO joins the elastic set here
	// because the detail pane below states the target version in full.
	var hard [colCount]int
	for c := range hard {
		hard[c] = min(minWidths[c], hardMin)
	}
	m.shrink(colVuln, colPackage, hard, w)
	m.shrink(colFixTo, colVuln, hard, w)

	m.bodyTop = chromeAbove
	m.bodyRows = max(1, h-chromeAbove-chromeBelow)
	m.bodyRows = min(m.bodyRows, len(m.rows))

	x := margin + 1 // past the leading space and the left border
	for c := 0; c < colAction; c++ {
		if m.shown[c] {
			x += m.widths[c] + 3
		}
	}
	m.actionX0, m.actionX1 = x, x+m.widths[colAction]+2

	m.scrollIntoView()
}

// shrink narrows the two elastic columns, alternating so the wider one gives
// way first, until the table fits w or both reach their floor.
func (m *model) shrink(a, b int, floors [colCount]int, w int) {
	for m.tableWidth() > w {
		c := a
		if m.widths[b] > m.widths[a] {
			c = b
		}
		if m.widths[c] <= floors[c] {
			return
		}
		m.widths[c]--
	}
}

// tableWidth is the rendered width of one table line: the margin, then
// "│ " + cell + " " per visible column, plus the closing "│".
func (m *model) tableWidth() int {
	n := margin + 1
	for c, cw := range m.widths {
		if m.shown[c] {
			n += cw + 3
		}
	}
	return n
}

func (m *model) grow(col int, s string) {
	if n := runeLen(s); n > m.widths[col] {
		m.widths[col] = n
	}
}

func (m *model) scrollIntoView() {
	if m.cursor < m.top {
		m.top = m.cursor
	}
	if m.cursor >= m.top+m.bodyRows {
		m.top = m.cursor - m.bodyRows + 1
	}
	if maxTop := len(m.rows) - m.bodyRows; m.top > maxTop {
		m.top = max(0, maxTop)
	}
	if m.top < 0 {
		m.top = 0
	}
}

// actionLabel is the ACTION cell for a package: what will happen, or what did.
func (m *model) actionLabel(target int) string {
	switch st := m.state[target]; {
	case st.applied:
		return "✔ fixed"
	case st.err != "":
		return "! failed"
	case !m.targets[target].Fixable:
		return "— manual"
	default:
		return "[ Fix ]"
	}
}

// ── Event handling ──────────────────────────────────────────────────────────

func (m *model) handle(ev event) {
	switch ev.Kind {
	case evtUp:
		m.move(-1)
	case evtDown:
		m.move(1)
	case evtPageUp:
		m.move(-m.bodyRows)
	case evtPageDown:
		m.move(m.bodyRows)
	case evtHome:
		m.cursor = 0
	case evtEnd:
		m.cursor = len(m.rows) - 1
	case evtActivate:
		m.applyCursor()
	case evtFixAll:
		m.applyAll()
	case evtHelp:
		m.setStatus(statusNone, "↑/↓ or j/k move · enter or click [ Fix ] applies one · a applies every fixable package · q quits")
	case evtClick:
		m.click(ev)
	}
	m.scrollIntoView()
}

func (m *model) move(d int) {
	m.cursor = clamp(m.cursor+d, 0, len(m.rows)-1)
}

// click maps a screen position onto a row. Any click inside the table moves the
// cursor; a click in the ACTION column also applies the fix, including on a
// package's continuation rows — the button is drawn once per group, but the
// whole column is a plausible place to aim.
func (m *model) click(ev event) {
	idx := m.top + (ev.Row - m.bodyTop)
	if ev.Row < m.bodyTop || idx < 0 || idx >= len(m.rows) || idx >= m.top+m.bodyRows {
		return
	}
	m.cursor = idx
	if ev.Col >= m.actionX0 && ev.Col < m.actionX1 {
		m.applyCursor()
	}
}

func (m *model) applyCursor() {
	if len(m.rows) == 0 {
		return
	}
	t := m.rows[m.cursor].target
	if !m.apply(t) {
		return
	}
	st := m.state[t]
	if st.applied {
		m.setStatus(statusGood, fmt.Sprintf("%s → %s in %s:%d",
			m.targets[t].Package, m.targets[t].Fixed, st.result.File, st.result.Line))
	} else {
		m.setStatus(statusBad, st.err)
	}
}

// applyAll fixes every package that still can be, and reports the tally rather
// than the last message — with twenty packages, one line about the twentieth
// says nothing about the other nineteen.
func (m *model) applyAll() {
	done, failed, skipped := 0, 0, 0
	for i := range m.targets {
		switch {
		case m.state[i].applied:
			continue
		case !m.targets[i].Fixable:
			skipped++
			continue
		}
		if !m.apply(i) {
			continue
		}
		if m.state[i].applied {
			done++
		} else {
			failed++
		}
	}
	switch {
	case done == 0 && failed == 0 && skipped == 0:
		m.setStatus(statusNone, "nothing left to fix")
	case failed > 0:
		m.setStatus(statusBad, fmt.Sprintf("fixed %d, %d failed, %d need a manual change", done, failed, skipped))
	case skipped > 0:
		m.setStatus(statusGood, fmt.Sprintf("fixed %d package(s); %d need a manual change", done, skipped))
	default:
		m.setStatus(statusGood, fmt.Sprintf("fixed %d package(s)", done))
	}
}

// apply performs one fix and records the result. Reports whether it ran at all
// (an already-fixed or unfixable package is not retried).
func (m *model) apply(i int) bool {
	if m.state[i].applied {
		m.setStatus(statusNone, m.targets[i].Package+" is already fixed")
		return false
	}
	if !m.targets[i].Fixable {
		reason := m.targets[i].Reason
		if reason == "" {
			reason = "no manifest pin to rewrite"
		}
		m.setStatus(statusBad, m.targets[i].Package+": "+reason)
		return false
	}
	res, err := fix.Apply(m.root, m.targets[i])
	if err != nil {
		m.state[i].err = err.Error()
		m.outcome.Failed++
		return true
	}
	m.state[i] = rowState{applied: true, result: res}
	m.outcome.Applied = append(m.outcome.Applied, res)
	m.outcome.Fixed = append(m.outcome.Fixed, m.targets[i].Package)
	return true
}

func (m *model) setStatus(k statusKind, s string) { m.status, m.statusK = s, k }

// ── Rendering ───────────────────────────────────────────────────────────────

func (m *model) render(w, h int) string {
	if w < MinWidth || h < MinHeight {
		return m.tooSmall(w, h)
	}
	var b strings.Builder
	fixable, remaining := m.counts()

	const brand = "AIROM · fix advisories"
	b.WriteString(" " + m.pal.Heading.S(truncate(brand, w-margin)))
	if room := w - margin - runeLen(brand) - 2; room > 0 {
		b.WriteString("  " + m.pal.Dim.S(truncate(m.root, room)))
	}
	b.WriteString("\r\n")

	line := fmt.Sprintf("%s across %s · %d fixable",
		count(m.totalVulns(), "advisory", "advisories"),
		count(len(m.targets), "package", "packages"), fixable)
	if done := len(m.targets) - remaining; done > 0 {
		line += fmt.Sprintf(" · %d fixed this session", done)
	}
	b.WriteString(" " + m.pal.Dim.S(truncate(line, w-margin)) + "\r\n\r\n")

	b.WriteString(" " + m.border("┌", "┬", "┐") + "\r\n")
	b.WriteString(" " + m.headerRow() + "\r\n")
	b.WriteString(" " + m.border("├", "┼", "┤") + "\r\n")
	for i := m.top; i < m.top+m.bodyRows && i < len(m.rows); i++ {
		b.WriteString(" " + m.bodyRow(i) + "\r\n")
	}
	b.WriteString(" " + m.border("└", "┴", "┘") + "\r\n")

	if hidden := len(m.rows) - m.bodyRows; hidden > 0 {
		b.WriteString(" " + m.pal.Dim.S(truncate(
			fmt.Sprintf("%d more row(s) — scroll with ↑/↓", hidden), w-margin)) + "\r\n")
	} else {
		b.WriteString("\r\n")
	}
	b.WriteString(" " + m.detail(w) + "\r\n")
	b.WriteString(" " + m.statusLine(w) + "\r\n")
	b.WriteString(" " + m.pal.Dim.S(truncate(
		"↑/↓ move · enter or click [ Fix ] · a fix all · ? help · q quit", w-margin)))
	return b.String()
}

// tooSmall replaces the table on a terminal that cannot hold it, naming both
// ways out. Drawing a frame larger than the screen would leave every click
// landing on the wrong row — the alternate screen scrolls, and the row
// arithmetic is computed from a position that no longer holds — which is worse
// than drawing no table at all.
func (m *model) tooSmall(w, h int) string {
	fixable, _ := m.counts()
	// The way out leads each line it appears on, because these lines are the
	// ones most likely to be truncated — advice cut off mid-sentence is not
	// advice.
	lines := []string{
		m.pal.Heading.S("AIROM · fix advisories"),
		fmt.Sprintf("%d fixable of %s", fixable, count(len(m.targets), "package", "packages")),
		"",
		fmt.Sprintf("Too small: %dx%d, need %dx%d.", w, h, MinWidth, MinHeight),
		"Resize this window, or:",
		"--fix-all applies every fix.",
		"",
		m.pal.Dim.S("q quit"),
	}
	if h > 0 && len(lines) > h {
		lines = lines[:h] // never overflow the screen this notice is about
	}
	for i, l := range lines {
		lines[i] = " " + truncate(l, max(1, w-margin))
	}
	return strings.Join(lines, "\r\n")
}

func (m *model) counts() (fixable, remaining int) {
	for i, t := range m.targets {
		if m.state[i].applied {
			continue
		}
		remaining++
		if t.Fixable {
			fixable++
		}
	}
	return fixable, remaining
}

func (m *model) totalVulns() int {
	n := 0
	for _, t := range m.targets {
		n += len(t.Vulns)
	}
	return n
}

func (m *model) border(left, mid, right string) string {
	parts := make([]string, 0, colCount)
	for c, cw := range m.widths {
		if m.shown[c] {
			parts = append(parts, strings.Repeat("─", cw+2))
		}
	}
	return left + strings.Join(parts, mid) + right
}

func (m *model) headerRow() string {
	cells := make([]string, 0, colCount)
	for c, hd := range headers {
		if !m.shown[c] {
			continue
		}
		cells = append(cells, " "+m.pal.Bold.S(pad(truncate(hd, m.widths[c]), m.widths[c]))+" ")
	}
	return "│" + strings.Join(cells, "│") + "│"
}

// bodyRow renders one table line. The per-package columns are blank on
// continuation rows, so a package with nine advisories states its name, its
// version, and its button once.
//
// "Once" means once per SCREEN, not once per group: the topmost visible row
// always redraws them, because a package with twenty advisories scrolls its own
// header off and would otherwise leave a whole screen of CVEs belonging to
// nothing, with no button to press.
func (m *model) bodyRow(i int) string {
	r := m.rows[i]
	t := m.targets[r.target]
	st := m.state[r.target]
	selected := i == m.cursor
	leads := r.first || i == m.top

	var id, sev string
	if r.vuln >= 0 {
		id = t.Vulns[r.vuln].ID
		sev = strings.ToUpper(string(t.Vulns[r.vuln].Severity))
	}

	var raw [colCount]string
	if leads {
		raw[colPackage] = t.Package
		raw[colInstalled] = t.Current
		raw[colFixTo] = fixToLabel(t)
		raw[colAction] = m.actionLabel(r.target)
	}
	raw[colVuln] = id
	raw[colSeverity] = sev

	cells := make([]string, 0, colCount)
	for c := range raw {
		if !m.shown[c] {
			continue
		}
		text := pad(truncate(raw[c], m.widths[c]), m.widths[c])
		if !selected { // a reverse-video row must not fight per-cell colors
			switch c {
			case colSeverity:
				text = m.severityStyle(raw[colSeverity]).S(text)
			case colFixTo:
				switch {
				case st.applied:
					text = m.pal.Good.S(text)
				case raw[c] == "":
				case t.Major:
					text = m.pal.Warn.S(text) // an API break, not a patch
				default:
					text = m.pal.Accent.S(text)
				}
			case colAction:
				text = m.actionStyle(r.target).S(text)
			}
		}
		cells = append(cells, " "+text+" ")
	}
	line := "│" + strings.Join(cells, "│") + "│"
	if selected {
		return m.pal.Selected.S(line)
	}
	return line
}

func (m *model) severityStyle(sev string) tui.Style {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return m.pal.Bad
	case "MEDIUM":
		return m.pal.Warn
	case "LOW":
		return m.pal.Dim
	default:
		return m.pal.Dim
	}
}

func (m *model) actionStyle(target int) tui.Style {
	switch st := m.state[target]; {
	case st.applied:
		return m.pal.Good
	case st.err != "":
		return m.pal.Bad
	case !m.targets[target].Fixable:
		return m.pal.Dim
	default:
		return m.pal.Accent
	}
}

// detail explains the selected row: the advisory on it, and the exact manifest
// edit its Fix would make. The second half is the honest part of the button —
// the user can read the line before pressing it.
func (m *model) detail(w int) string {
	if len(m.rows) == 0 {
		return ""
	}
	r := m.rows[m.cursor]
	t := m.targets[r.target]

	head := ""
	if r.vuln >= 0 {
		v := t.Vulns[r.vuln]
		head = v.ID
		if v.Score > 0 {
			head += fmt.Sprintf(" (CVSS %.1f)", v.Score)
		}
		if v.Summary != "" {
			head += " · " + v.Summary
		}
	}

	var edit string
	switch st := m.state[r.target]; {
	case st.applied:
		edit = fmt.Sprintf("%s:%d  %s", st.result.File, st.result.Line, st.result.After)
	case !t.Fixable:
		edit = "no manifest pin to rewrite: " + t.Reason
	default:
		edit = fmt.Sprintf("%s:%d  %s   →   %s %s",
			t.File, t.Line, strings.TrimSpace(t.Snippet), t.Package, t.Fixed)
		if t.Major {
			edit += "   [major bump — review for breaking changes]"
		}
	}
	return truncate(head, w-margin) + "\r\n " + m.pal.Dim.S(truncate(edit, w-margin))
}

func (m *model) statusLine(w int) string {
	if m.status == "" {
		return ""
	}
	s := truncate(m.status, w-margin-2) // the leading marker costs two cells
	switch m.statusK {
	case statusGood:
		return m.pal.Good.S("✔ " + s)
	case statusBad:
		return m.pal.Bad.S("✖ " + s)
	default:
		return m.pal.Dim.S(s)
	}
}

// ── Small helpers ───────────────────────────────────────────────────────────

// fixToLabel is the FIX TO cell: the target version, marked when reaching it
// means crossing a major boundary.
//
// The marker is the word, not a warning sign: U+26A0 is East-Asian Ambiguous
// width, so half the terminals in the world would render it two cells wide and
// shear the column it sits in. It also has to survive NO_COLOR, where the
// yellow this cell is drawn in says nothing.
func fixToLabel(t fix.Target) string {
	if t.Major {
		return t.Fixed + " (major)"
	}
	return t.Fixed
}

// runeLen measures a string in TERMINAL CELLS, not runes, via the one
// implementation in internal/tui.
//
// The distinction decides where a row lands on screen. A CJK package name or an
// emoji in the scan root is two cells wide but one rune; measured in runes the
// line runs past the terminal, wraps, and every row below it sits one line lower
// than the click handler computes — the same class of failure as a frame one
// line too tall. fixToLabel already refuses U+26A0 for exactly this reason; the
// measuring helpers have to agree with it.
func runeLen(s string) int { return tui.DispWidth(s) }

func pad(s string, w int) string {
	if n := runeLen(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// truncate shortens s to w terminal cells, marking the cut with an ellipsis so a
// clipped value never reads as a complete one. A wide rune that would straddle
// the limit is dropped rather than half-drawn.
func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if runeLen(s) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := tui.DispWidth(string(r))
		if used+rw > w-1 { // reserve one cell for the ellipsis
			break
		}
		b.WriteRune(r)
		used += rw
	}
	return b.String() + "…"
}

func clamp(v, lo, hi int) int {
	if hi < lo {
		return lo
	}
	return min(max(v, lo), hi)
}

func count(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Report renders the non-interactive view of a plan: what a --fix-all run did,
// or what the table would have offered on a terminal it could not open.
//
// Sorted most-severe-first, like every other CVE surface — and like the table
// this stands in for. Sorting by name instead would put a low finding above a
// critical one in the two views a user falls back to when they cannot see the
// table, which is where the ordering matters most.
func Report(targets []fix.Target) string {
	ts := append([]fix.Target(nil), targets...)
	sort.SliceStable(ts, func(i, j int) bool {
		if ri, rj := fix.SeverityRank(ts[i].Severity), fix.SeverityRank(ts[j].Severity); ri != rj {
			return ri > rj
		}
		return ts[i].Package < ts[j].Package
	})
	var b strings.Builder
	for _, t := range ts {
		if t.Fixable {
			fmt.Fprintf(&b, "  %s\n", t.String())
		} else {
			fmt.Fprintf(&b, "  %s %s: no automatic fix (%s)\n", t.Package, t.Current, t.Reason)
		}
	}
	return b.String()
}
