// Package tablew writes the human-readable table (ARCHITECTURE.md §11): a boxed
// scan-summary panel (counts by kind and by risk severity) followed by a
// box-drawn component table, sorted by kind then name. The scan-root
// application component is omitted (it is metadata, not a finding). Verbose
// mode expands the file:line occurrences under each row.
package tablew

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

func init() {
	writer.Register("table", func(o writer.Options) writer.Writer { return Writer{wide: o.TableWide} })
}

// Writer renders the table format.
type Writer struct{ wide bool }

// Format implements writer.Writer.
func (Writer) Format() string { return "table" }

// Write emits the summary panel and component table.
func (t Writer) Write(w io.Writer, inv *airom.Inventory) error {
	comps := make([]airom.Component, 0, len(inv.Components))
	for _, c := range inv.Components {
		if c.Kind == airom.KindApplication {
			continue
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
		if n := len(inv.Unknowns); n > 0 {
			fmt.Fprintf(w, "\n%d file(s) could not be fully processed (see --stats or the json output).\n", n)
		}
		return nil
	}

	writeSummary(w, inv, comps)

	// The RISK/FLAGS columns appear only when a scan surfaces at least one
	// artifact risk, so risk-free output stays narrow.
	anyRisk := false
	for _, c := range comps {
		if len(c.Risks) > 0 {
			anyRisk = true
			break
		}
	}

	fmt.Fprintln(w)
	writeTable(w, comps, anyRisk)

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

	if n := len(inv.Unknowns); n > 0 {
		fmt.Fprintf(w, "\n%d file(s) could not be fully processed (see --stats or the json output).\n", n)
	}
	return nil
}

// writeSummary renders the boxed scan-summary panel: headline counts, a
// per-kind breakdown, and a by-severity breakdown of the artifact risks.
func writeSummary(w io.Writer, inv *airom.Inventory, comps []airom.Component) {
	var lines []string
	lines = append(lines,
		kv("Target", truncate(inv.Source.Target, 58)),
		kv("Components", fmt.Sprintf("%d", len(comps))))
	if r := len(inv.Relationships); r > 0 {
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

	// By Severity — each risk-bearing component counted at its highest severity.
	sev := map[airom.RiskSeverity]int{airom.RiskHigh: 0, airom.RiskMedium: 0, airom.RiskLow: 0}
	for _, c := range comps {
		if s, ok := topSeverity(c); ok {
			sev[s]++
		}
	}
	lines = append(lines, "", "By Severity")
	for _, s := range []airom.RiskSeverity{airom.RiskHigh, airom.RiskMedium, airom.RiskLow} {
		lines = append(lines, fmt.Sprintf("  %-18s %d", s, sev[s]))
	}

	summaryBox(w, "Scan Summary", lines)
}

// writeTable renders the component table with box-drawing borders, columns
// sized to their widest cell (full names are never truncated).
func writeTable(w io.Writer, comps []airom.Component, anyRisk bool) {
	headers := []string{"KIND", "NAME", "VERSION", "PROVIDER", "CONF"}
	if anyRisk {
		headers = append(headers, "RISK", "FLAGS")
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
		if anyRisk {
			row = append(row, severityCell(c), flagsCell(c))
		}
		row = append(row, locationCell(c), fmt.Sprintf("%d occ", len(c.Evidence.Occurrences)))
		rows = append(rows, row)
	}
	boxTable(w, headers, rows)
}

// ── rendering helpers ───────────────────────────────────────────────────────

func runeLen(s string) int { return utf8.RuneCountInString(s) }

func kv(k, v string) string { return fmt.Sprintf("%-13s %s", k, v) }

// summaryBox draws a single-column box with the title set into the top border.
func summaryBox(w io.Writer, title string, lines []string) {
	inner := runeLen("─ " + title + " ")
	for _, l := range lines {
		if runeLen(l) > inner {
			inner = runeLen(l)
		}
	}
	head := "─ " + title + " "
	fmt.Fprintln(w, "┌"+head+strings.Repeat("─", inner-runeLen(head)+2)+"┐")
	for _, l := range lines {
		fmt.Fprintln(w, "│ "+l+strings.Repeat(" ", inner-runeLen(l))+" │")
	}
	fmt.Fprintln(w, "└"+strings.Repeat("─", inner+2)+"┘")
}

// boxTable draws a bordered table with per-column widths.
func boxTable(w io.Writer, headers []string, rows [][]string) {
	n := len(headers)
	width := make([]int, n)
	for i, h := range headers {
		width[i] = runeLen(h)
	}
	for _, r := range rows {
		for i := 0; i < n; i++ {
			if l := runeLen(r[i]); l > width[i] {
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
			b.WriteString(" " + cells[i] + strings.Repeat(" ", width[i]-runeLen(cells[i])) + " │")
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

// topSeverity returns the highest severity among a component's risks.
func topSeverity(c airom.Component) (airom.RiskSeverity, bool) {
	if len(c.Risks) == 0 {
		return "", false
	}
	top := c.Risks[0].Severity
	for _, r := range c.Risks[1:] {
		if severityRank(r.Severity) > severityRank(top) {
			top = r.Severity
		}
	}
	return top, true
}

// severityCell renders the highest severity as a plain bucket, or "-".
func severityCell(c airom.Component) string {
	if s, ok := topSeverity(c); ok {
		return string(s)
	}
	return "-"
}

// flagsCell renders the risk slugs (pickle-import, unsafe-load, …) sorted and
// deduplicated, or "-" when risk-free.
func flagsCell(c airom.Component) string {
	if len(c.Risks) == 0 {
		return "-"
	}
	seen := map[string]bool{}
	var slugs []string
	for _, r := range c.Risks {
		s := airom.RiskByID(r.ID).Slug
		if !seen[s] {
			seen[s] = true
			slugs = append(slugs, s)
		}
	}
	sort.Strings(slugs)
	return strings.Join(slugs, ", ")
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

func severityRank(s airom.RiskSeverity) int {
	switch s {
	case airom.RiskHigh:
		return 3
	case airom.RiskMedium:
		return 2
	default:
		return 1
	}
}
