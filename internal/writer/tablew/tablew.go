// Package tablew writes the human-readable table (ARCHITECTURE.md §11): a boxed
// scan-summary panel (counts by kind, and by CVE severity when the CVE overlay
// ran) followed by a box-drawn component table, sorted by kind then name, and a
// per-CVE detail table when vulnerabilities were found. The scan-root
// application component is omitted (it is metadata, not a finding). Verbose mode
// expands the file:line occurrences under each row.
package tablew

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

func init() {
	writer.Register("table", func(o writer.Options) writer.Writer {
		return Writer{wide: o.TableWide, includeTests: o.IncludeTests}
	})
}

// Writer renders the table format.
type Writer struct{ wide, includeTests bool }

// Format implements writer.Writer.
func (Writer) Format() string { return "table" }

// Write emits the summary panel and component table.
func (t Writer) Write(w io.Writer, inv *airom.Inventory) error {
	comps := make([]airom.Component, 0, len(inv.Components))
	hiddenTests := 0
	for _, c := range inv.Components {
		if c.Kind == airom.KindApplication {
			continue
		}
		if c.TestOnly && !t.includeTests {
			hiddenTests++
			continue
		}
		if !t.includeTests {
			// Same reason SARIF prunes: a real dependency that also appears in
			// fixtures must not report a testdata/ LOCATION, and "5 occ" must
			// not count sightings the default view is filtering out.
			c.Evidence.Occurrences = airom.ProductionOccurrences(c.Evidence.Occurrences)
		}
		comps = append(comps, c)
	}
	sort.SliceStable(comps, func(i, j int) bool {
		if comps[i].Kind != comps[j].Kind {
			return comps[i].Kind < comps[j].Kind
		}
		return comps[i].Name < comps[j].Name
	})

	fmt.Fprintf(w, "AI Bill of Materials — %s\n\n", inv.Source.Target)

	if len(comps) == 0 {
		fmt.Fprintf(w, "No AI components found in %s.\n", inv.Source.Target)
		// Without this line, a tree whose AI lives entirely in fixtures reads as
		// "there is no AI here" — the one sentence the scan must not imply when
		// it found 180 things and chose not to show them.
		writeHiddenTestNote(w, hiddenTests)
		if n := len(inv.Unknowns); n > 0 {
			fmt.Fprintf(w, "\n%d file(s) could not be fully processed (see --stats or the json output).\n", n)
		}
		return nil
	}

	writeSummary(w, inv, comps)

	// The VULN and EOL columns appear only when a scan surfaces something, so
	// clean output stays narrow.
	anyVuln, anyEOL := false, false
	for _, c := range comps {
		if len(c.Vulnerabilities) > 0 {
			anyVuln = true
		}
		if eolReportable(c) {
			anyEOL = true
		}
	}

	fmt.Fprintln(w)
	writeTable(w, comps, anyVuln, anyEOL)

	// The per-CVE detail table (library, id, severity, fix, title) follows the
	// component table when the CVE overlay found anything.
	if anyVuln {
		writeVulnTable(w, comps)
	}
	// Then the lifecycle detail table: what stops working, when, and what to
	// move to.
	if anyEOL {
		writeEOLTable(w, comps)
	}

	if t.wide {
		fmt.Fprintln(w)
		for _, c := range comps {
			fmt.Fprintf(w, "%s %s:\n", c.Kind, name(c))
			for _, o := range c.Evidence.Occurrences {
				loc := o.Location.Path
				if o.Location.Line > 0 {
					loc = fmt.Sprintf("%s:%d", o.Location.Path, o.Location.Line)
				}
				fmt.Fprintf(w, "    %s  [%s]\n", loc, o.DetectorID)
			}
		}
	}

	writeHiddenTestNote(w, hiddenTests)

	if n := len(inv.Unknowns); n > 0 {
		fmt.Fprintf(w, "\n%d file(s) could not be fully processed (see --stats or the json output).\n", n)
	}
	return nil
}

// writeHiddenTestNote states what the table left out. Filtering silently would
// make a narrow scan indistinguishable from a thorough one, which is the same
// failure as reporting fixtures as production AI — just in the other direction.
// The components are still in the JSON and CycloneDX output either way.
func writeHiddenTestNote(w io.Writer, hidden int) {
	if hidden == 0 {
		return
	}
	fmt.Fprintf(w, "\n%d component(s) found only in test scaffolding, not shown (--include-tests to include them).\n", hidden)
}

// visibleRelationships counts edges whose endpoints both survived filtering.
// The scan root is always an endpoint of the "application uses X" edges and is
// never in comps, so it counts as visible — it is the target, not a hidden
// finding.
func visibleRelationships(inv *airom.Inventory, comps []airom.Component) int {
	shown := make(map[airom.ID]bool, len(comps)+1)
	shown[inv.Root] = true
	for _, c := range comps {
		shown[c.ID] = true
	}
	n := 0
	for _, r := range inv.Relationships {
		if shown[r.From] && shown[r.To] {
			n++
		}
	}
	return n
}

// writeSummary renders the boxed scan-summary panel: headline counts, a
// per-kind breakdown, and a by-severity breakdown of the artifact risks.
func writeSummary(w io.Writer, inv *airom.Inventory, comps []airom.Component) {
	var lines []string
	lines = append(lines,
		kv("Target", truncate(inv.Source.Target, 58)),
		kv("Components", fmt.Sprintf("%d", len(comps))))
	// Count only edges whose BOTH endpoints are on screen. "Components 4 /
	// Relationships 4" where two edges terminate on hidden components is a
	// number describing a different graph than the table under it.
	if r := visibleRelationships(inv, comps); r > 0 {
		lines = append(lines, kv("Relationships", fmt.Sprintf("%d", r)))
	}
	lines = append(lines, kv("Files", fmt.Sprintf("%d scanned", inv.Stats.FilesProcessed)))

	// By Type — kinds by descending count, then name (deterministic).
	byKind := map[airom.ComponentKind]int{}
	for _, c := range comps {
		byKind[c.Kind]++
	}
	kinds := make([]airom.ComponentKind, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool {
		if byKind[kinds[i]] != byKind[kinds[j]] {
			return byKind[kinds[i]] > byKind[kinds[j]]
		}
		return kinds[i] < kinds[j]
	})
	lines = append(lines, "", "By Type")
	for _, k := range kinds {
		lines = append(lines, fmt.Sprintf("  %-18s %d", k, byKind[k]))
	}

	// Vulnerabilities — total CVEs by severity bucket (the CVE overlay). Shown
	// only when the scan surfaced CVEs, and only the non-empty buckets.
	cveBySev := map[airom.VulnSeverity]int{}
	total := 0
	for _, c := range comps {
		for _, v := range c.Vulnerabilities {
			cveBySev[v.Severity]++
			total++
		}
	}
	if total > 0 {
		lines = append(lines, "", "Vulnerabilities")
		lines = append(lines, fmt.Sprintf("  %-18s %d", "total", total))
		for _, s := range airom.VulnSeverities() {
			if n := cveBySev[s]; n > 0 {
				lines = append(lines, fmt.Sprintf("  %-18s %d", s, n))
			}
		}
	}

	// Model lifecycle — counted only for states that are findings, so a healthy
	// scan stays quiet. A model that stopped answering belongs in the first
	// thing a reader looks at, not only in a table further down.
	eolByState := map[airom.EOLState]int{}
	eolTotal := 0
	for _, c := range comps {
		if eolReportable(c) {
			eolByState[c.EOL.State]++
			eolTotal++
		}
	}
	if eolTotal > 0 {
		lines = append(lines, "", "Model lifecycle")
		for _, s := range airom.EOLStates() {
			if n := eolByState[s]; n > 0 {
				lines = append(lines, fmt.Sprintf("  %-18s %d", s, n))
			}
		}
	}

	summaryBox(w, "Scan Summary", lines)
}

// writeTable renders the component table with box-drawing borders, columns
// sized to their widest cell (full names are never truncated).
func writeTable(w io.Writer, comps []airom.Component, anyVuln, anyEOL bool) {
	headers := []string{"KIND", "NAME", "VERSION", "PROVIDER", "CONF"}
	if anyVuln {
		headers = append(headers, "VULN")
	}
	if anyEOL {
		headers = append(headers, "EOL")
	}
	headers = append(headers, "LOCATION", "EVIDENCE")

	rows := make([][]string, 0, len(comps))
	for _, c := range comps {
		version, _ := c.Version.Value()
		provider, _ := c.Provider.Value()
		row := []string{
			string(c.Kind), name(c), dash(version), dash(provider),
			writer.FormatConfidence(c.Confidence),
		}
		if anyVuln {
			row = append(row, vulnCell(c))
		}
		if anyEOL {
			row = append(row, eolCell(c))
		}
		row = append(row, locationCell(c), fmt.Sprintf("%d occ", len(c.Evidence.Occurrences)))
		rows = append(rows, row)
	}
	boxTable(w, headers, rows)
}

// ── rendering helpers ───────────────────────────────────────────────────────

// runeLen counts runes — used where a rune count is what's wanted (wrap width,
// tail truncation). Column alignment uses dispWidth instead.
func runeLen(s string) int { return utf8.RuneCountInString(s) }

// dispWidth approximates the terminal-cell width of s: East-Asian wide/fullwidth
// runes and most emoji take two cells, combining/enclosing marks zero, the rest
// one. It is an approximation (not the full Unicode width tables), but it keeps
// the box drawings rectangular for the non-ASCII advisory titles OSV can carry —
// pure-ASCII output (every golden) is unaffected, since there dispWidth == the
// rune count.
func dispWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case r == 0:
		case unicode.In(r, unicode.Mn, unicode.Me): // combining / enclosing marks
		case isWide(r):
			w += 2
		default:
			w++
		}
	}
	return w
}

// isWide reports whether r occupies two terminal cells (CJK, Hangul, Kana,
// fullwidth forms, and the common emoji/symbol blocks).
func isWide(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0x303E,   // CJK radicals … Kangxi
		r >= 0x3041 && r <= 0x33FF,   // Hiragana … CJK compat
		r >= 0x3400 && r <= 0x4DBF,   // CJK Ext A
		r >= 0x4E00 && r <= 0x9FFF,   // CJK Unified
		r >= 0xA000 && r <= 0xA4CF,   // Yi
		r >= 0xAC00 && r <= 0xD7A3,   // Hangul syllables
		r >= 0xF900 && r <= 0xFAFF,   // CJK compat ideographs
		r >= 0xFE30 && r <= 0xFE4F,   // CJK compat forms
		r >= 0xFF00 && r <= 0xFF60,   // Fullwidth forms
		r >= 0xFFE0 && r <= 0xFFE6,   // Fullwidth signs
		r >= 0x1F300 && r <= 0x1FAFF, // emoji & pictographs
		r >= 0x20000 && r <= 0x3FFFD: // CJK Ext B+
		return true
	}
	return false
}

func kv(k, v string) string { return fmt.Sprintf("%-13s %s", k, v) }

// summaryBox draws a single-column box with the title set into the top border.
func summaryBox(w io.Writer, title string, lines []string) {
	inner := dispWidth("─ " + title + " ")
	for _, l := range lines {
		if dispWidth(l) > inner {
			inner = dispWidth(l)
		}
	}
	head := "─ " + title + " "
	fmt.Fprintln(w, "┌"+head+strings.Repeat("─", inner-dispWidth(head)+2)+"┐")
	for _, l := range lines {
		fmt.Fprintln(w, "│ "+l+strings.Repeat(" ", inner-dispWidth(l))+" │")
	}
	fmt.Fprintln(w, "└"+strings.Repeat("─", inner+2)+"┘")
}

// boxTable draws a bordered table with per-column widths.
func boxTable(w io.Writer, headers []string, rows [][]string) {
	n := len(headers)
	width := make([]int, n)
	for i, h := range headers {
		width[i] = dispWidth(h)
	}
	for _, r := range rows {
		for i := 0; i < n; i++ {
			if l := dispWidth(r[i]); l > width[i] {
				width[i] = l
			}
		}
	}
	rule := func(l, m, r string) string {
		var b strings.Builder
		b.WriteString(l)
		for i := 0; i < n; i++ {
			b.WriteString(strings.Repeat("─", width[i]+2))
			if i < n-1 {
				b.WriteString(m)
			}
		}
		b.WriteString(r)
		return b.String()
	}
	row := func(cells []string) string {
		var b strings.Builder
		b.WriteString("│")
		for i := 0; i < n; i++ {
			b.WriteString(" " + cells[i] + strings.Repeat(" ", width[i]-dispWidth(cells[i])) + " │")
		}
		return b.String()
	}
	fmt.Fprintln(w, rule("┌", "┬", "┐"))
	fmt.Fprintln(w, row(headers))
	fmt.Fprintln(w, rule("├", "┼", "┤"))
	for _, r := range rows {
		fmt.Fprintln(w, row(r))
	}
	fmt.Fprintln(w, rule("└", "┴", "┘"))
}

// boxMultiline draws a bordered table whose cells may each span several lines
// (rows is [row][column][line]). A logical row is as tall as its tallest cell,
// shorter cells pad with blanks. mergeUp[r][c] (may be nil) marks a cell that
// visually merges with the one above it — its content is blanked and the rule
// between the two rows carries no horizontal segment under that column, so the
// two cells read as one spanning cell (Trivy-style).
func boxMultiline(w io.Writer, headers []string, rows [][][]string, mergeUp [][]bool) {
	n := len(headers)
	merged := func(r, c int) bool { return mergeUp != nil && r >= 0 && mergeUp[r][c] }

	width := make([]int, n)
	for i, h := range headers {
		width[i] = dispWidth(h)
	}
	for _, r := range rows {
		for i := 0; i < n; i++ {
			for _, line := range r[i] {
				if l := dispWidth(line); l > width[i] {
					width[i] = l
				}
			}
		}
	}
	// A full rule (top/header/bottom): every column separated.
	fullRule := func(l, m, rr string) string {
		var b strings.Builder
		b.WriteString(l)
		for i := 0; i < n; i++ {
			b.WriteString(strings.Repeat("─", width[i]+2))
			if i < n-1 {
				b.WriteString(m)
			}
		}
		b.WriteString(rr)
		return b.String()
	}
	// A between-rows rule: columns merged into the row below carry spaces (the
	// cell continues) instead of ─, and the junctions bend accordingly.
	spanRule := func(rowBelow int) string {
		seg := func(c int) string {
			if merged(rowBelow, c) {
				return strings.Repeat(" ", width[c]+2)
			}
			return strings.Repeat("─", width[c]+2)
		}
		junction := func(leftMerged, rightMerged bool) string {
			switch {
			case !leftMerged && !rightMerged:
				return "┼"
			case !leftMerged && rightMerged:
				return "┤"
			case leftMerged && !rightMerged:
				return "├"
			default:
				return "│"
			}
		}
		var b strings.Builder
		if merged(rowBelow, 0) {
			b.WriteString("│")
		} else {
			b.WriteString("├")
		}
		for c := 0; c < n; c++ {
			b.WriteString(seg(c))
			if c < n-1 {
				b.WriteString(junction(merged(rowBelow, c), merged(rowBelow, c+1)))
			}
		}
		if merged(rowBelow, n-1) {
			b.WriteString("│")
		} else {
			b.WriteString("┤")
		}
		return b.String()
	}
	physical := func(r int, cells []string) string {
		var b strings.Builder
		b.WriteString("│")
		for i := 0; i < n; i++ {
			cell := cells[i]
			if merged(r, i) {
				cell = "" // a merged cell shows nothing; the row above owns the value
			}
			b.WriteString(" " + cell + strings.Repeat(" ", width[i]-dispWidth(cell)) + " │")
		}
		return b.String()
	}
	fmt.Fprintln(w, fullRule("┌", "┬", "┐"))
	fmt.Fprintln(w, physical(-1, headers)) // -1: header row never merges
	fmt.Fprintln(w, fullRule("├", "┼", "┤"))
	for ri, r := range rows {
		if ri > 0 {
			fmt.Fprintln(w, spanRule(ri))
		}
		height := 1
		for i := 0; i < n; i++ {
			if !merged(ri, i) && len(r[i]) > height {
				height = len(r[i])
			}
		}
		for k := 0; k < height; k++ {
			line := make([]string, n)
			for i := 0; i < n; i++ {
				if k < len(r[i]) {
					line[i] = r[i][k]
				}
			}
			fmt.Fprintln(w, physical(ri, line))
		}
	}
	fmt.Fprintln(w, fullRule("└", "┴", "┘"))
}

func name(c airom.Component) string {
	if c.Group != "" {
		return c.Group + "/" + c.Name
	}
	return c.Name
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// truncate keeps the tail of an over-long value (paths are most legible from
// the end), prefixing an ellipsis.
func truncate(s string, limit int) string {
	if runeLen(s) <= limit {
		return s
	}
	r := []rune(s)
	return "…" + string(r[len(r)-(limit-1):])
}

// writeVulnTable renders the per-CVE detail table (library, id, severity,
// status, installed/fixed version, and the wrapped advisory title + URL), one
// row per (component, CVE), most-severe first. The advisory title and URL wrap
// inside the TITLE column, so long summaries stay readable.
func writeVulnTable(w io.Writer, comps []airom.Component) {
	type vrow struct {
		lib, id    string
		sev        airom.VulnSeverity
		status     string
		installed  string
		fixed      string
		title, url string
	}
	var rows []vrow
	for _, c := range comps {
		installed, _ := c.Version.Value()
		for _, v := range c.Vulnerabilities {
			status := "affected"
			if v.Fixed != "" {
				status = "fixed"
			}
			rows = append(rows, vrow{
				lib: name(c), id: v.ID, sev: v.Severity, status: status,
				installed: dash(installed), fixed: dash(v.Fixed), title: v.Summary, url: v.URL,
			})
		}
	}
	if len(rows) == 0 {
		return
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if ri, rj := vulnRank(rows[i].sev), vulnRank(rows[j].sev); ri != rj {
			return ri > rj // most severe first
		}
		if rows[i].lib != rows[j].lib {
			return rows[i].lib < rows[j].lib
		}
		return rows[i].id < rows[j].id
	})

	const titleWidth = 48
	headers := []string{"LIBRARY", "VULNERABILITY", "SEVERITY", "STATUS", "INSTALLED", "FIXED", "TITLE"}
	cells := make([][][]string, 0, len(rows))
	for _, r := range rows {
		title := wrapText(r.title, titleWidth)
		if r.url != "" {
			title = append(title, r.url)
		}
		if len(title) == 0 {
			title = []string{"-"}
		}
		cells = append(cells, [][]string{
			{r.lib},
			{r.id},
			{strings.ToUpper(string(r.sev))},
			{r.status},
			{r.installed},
			{r.fixed},
			title,
		})
	}

	// Vertically merge the per-package columns (LIBRARY, INSTALLED, FIXED) across
	// adjacent rows that share a library, the way Trivy does — so a package with
	// many CVEs shows its name and versions once, spanning the group, instead of
	// repeating them on every row. VULNERABILITY, SEVERITY, STATUS, and TITLE
	// stay per-row so the individual findings remain separated.
	const colLibrary, colInstalled, colFixed = 0, 4, 5
	mergeUp := make([][]bool, len(rows))
	for i := range rows {
		m := make([]bool, len(headers))
		if i > 0 && rows[i].lib == rows[i-1].lib {
			m[colLibrary] = true
			m[colInstalled] = rows[i].installed == rows[i-1].installed
			m[colFixed] = rows[i].fixed == rows[i-1].fixed
		}
		mergeUp[i] = m
	}

	fmt.Fprintf(w, "\nVulnerabilities (%d)\n", len(rows))
	boxMultiline(w, headers, cells, mergeUp)
}

// wrapText greedily word-wraps s to lines of at most width runes, hard-splitting
// any single word longer than width. Returns nil for empty input.
func wrapText(s string, width int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var lines []string
	cur := ""
	for _, word := range strings.Fields(s) {
		for runeLen(word) > width { // hard-split an over-long word
			if cur != "" {
				lines = append(lines, cur)
				cur = ""
			}
			r := []rune(word)
			lines = append(lines, string(r[:width]))
			word = string(r[width:])
		}
		switch {
		case cur == "":
			cur = word
		case runeLen(cur)+1+runeLen(word) <= width:
			cur += " " + word
		default:
			lines = append(lines, cur)
			cur = word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// eolReportable reports whether a component carries a lifecycle finding worth a
// row: an announced retirement. "supported" is good news and "unknown" is no
// news — neither is a finding, and neither should widen the table.
func eolReportable(c airom.Component) bool {
	return c.EOL != nil && (c.EOL.State == airom.EOLRetired || c.EOL.State == airom.EOLDeprecated)
}

// eolCell renders the lifecycle column: "retired" for a model that is already
// gone, or "87d" — the deadline, which is the number that decides urgency — for
// one still being served.
func eolCell(c airom.Component) string {
	if !eolReportable(c) {
		return "-"
	}
	e := c.EOL
	if e.State == airom.EOLRetired {
		return string(airom.EOLRetired)
	}
	if e.DaysRemaining != nil && *e.DaysRemaining >= 0 {
		return fmt.Sprintf("%dd", *e.DaysRemaining)
	}
	return string(airom.EOLDeprecated)
}

// writeEOLTable renders the per-model lifecycle detail table, worst-first: what
// stops working, when, and what to move to. The replacement carries the target's
// own state when the catalog covers it, so the table never quietly recommends
// migrating onto a model that is itself retired.
func writeEOLTable(w io.Writer, comps []airom.Component) {
	type erow struct {
		model, provider string
		state           airom.EOLState
		shutdown, days  string
		replacement     string
		source          string
	}
	var rows []erow
	for _, c := range comps {
		if !eolReportable(c) {
			continue
		}
		e := c.EOL
		provider, _ := c.Provider.Value()
		shutdown, days := "-", "-"
		if e.Shutdown != nil {
			shutdown = e.Shutdown.String()
		}
		if e.DaysRemaining != nil {
			days = fmt.Sprintf("%d", *e.DaysRemaining)
		}
		repl := dash(e.Replacement)
		switch e.ReplacementState {
		case airom.EOLRetired:
			repl += " (retired)"
		case airom.EOLDeprecated:
			repl += " (deprecated)"
		}
		rows = append(rows, erow{
			model: name(c), provider: dash(provider), state: e.State,
			shutdown: shutdown, days: days, replacement: repl, source: e.SourceURL,
		})
	}
	if len(rows) == 0 {
		return
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if ri, rj := airom.EOLStateRank(rows[i].state), airom.EOLStateRank(rows[j].state); ri != rj {
			return ri > rj // retired before deprecated
		}
		// Soonest deadline first — but a deprecation with no date yet is the
		// LEAST urgent thing here, so it sinks below every dated row. Comparing
		// the rendered strings alone would do the opposite, since "-" sorts
		// before any digit, and float an undated row above a model that stops
		// answering next week.
		di, dj := rows[i].shutdown != "-", rows[j].shutdown != "-"
		if di != dj {
			return di
		}
		if di && rows[i].shutdown != rows[j].shutdown {
			return rows[i].shutdown < rows[j].shutdown
		}
		return rows[i].model < rows[j].model
	})

	headers := []string{"MODEL", "PROVIDER", "STATE", "SHUTDOWN", "DAYS", "MIGRATE TO"}
	tableRows := make([][]string, 0, len(rows))
	for _, r := range rows {
		tableRows = append(tableRows, []string{
			r.model, r.provider, strings.ToUpper(string(r.state)),
			r.shutdown, r.days, r.replacement,
		})
	}
	fmt.Fprintf(w, "\nModel lifecycle (%d)\n", len(rows))
	boxTable(w, headers, tableRows)

	// Provenance as a footnote rather than a column: every row from a provider
	// cites the same page, so repeating a wrapped URL per row would crowd out
	// the dates that actually decide anything — while dropping it entirely
	// would leave the claims unsourced.
	seen := map[string]bool{}
	var lines []string
	for _, c := range comps {
		if !eolReportable(c) || c.EOL.SourceURL == "" {
			continue
		}
		provider, _ := c.Provider.Value()
		line := fmt.Sprintf("  %s — %s", dash(provider), c.EOL.SourceURL)
		if c.EOL.Verified != nil {
			line += fmt.Sprintf(" (verified %s)", c.EOL.Verified)
		}
		if !seen[line] {
			seen[line] = true
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

// vulnCell renders the CVE overlay for a component as "<top-severity> (<n>)"
// — the highest CVSS bucket among its CVEs and the total count — or "-".
func vulnCell(c airom.Component) string {
	if len(c.Vulnerabilities) == 0 {
		return "-"
	}
	top := c.Vulnerabilities[0].Severity
	for _, v := range c.Vulnerabilities[1:] {
		if vulnRank(v.Severity) > vulnRank(top) {
			top = v.Severity
		}
	}
	return fmt.Sprintf("%s (%d)", top, len(c.Vulnerabilities))
}

func vulnRank(s airom.VulnSeverity) int {
	switch s {
	case airom.VulnCritical:
		return 4
	case airom.VulnHigh:
		return 3
	case airom.VulnMedium:
		return 2
	case airom.VulnLow:
		return 1
	default:
		return 0
	}
}

// locationCell renders the primary sighting — the lowest (path, line)
// occurrence, a deterministic pick — as source-relative "path:line" (or just
// "path" for a whole-file match), truncated from the tail. "-" when there is
// no located occurrence.
func locationCell(c airom.Component) string {
	occs := c.Evidence.Occurrences
	if len(occs) == 0 {
		return "-"
	}
	best := occs[0].Location
	for _, o := range occs[1:] {
		if locLess(o.Location, best) {
			best = o.Location
		}
	}
	if best.Path == "" {
		return "-"
	}
	loc := best.Path
	if best.Line > 0 {
		loc = fmt.Sprintf("%s:%d", best.Path, best.Line)
	}
	return truncate(loc, 40)
}

// locLess orders occurrences by path, then line — a total order over the
// fields that matter, so the primary sighting is stable across runs.
func locLess(a, b airom.Location) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	return a.Line < b.Line
}
