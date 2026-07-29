package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/airomhq/airom/internal/writer/tablew"
	"github.com/airomhq/airom/pkg/airom"
)

// Formats lists the diff output formats, default first.
func Formats() []string { return []string{"table", "markdown", "json"} }

// Render writes the diff in one format. Formats are pure projections of the
// same Result: table for terminals, markdown for PR comments, json for
// tooling.
func Render(w io.Writer, format string, r *Result) error {
	switch format {
	case "table":
		renderTable(w, r)
		return nil
	case "markdown":
		renderMarkdown(w, r)
		return nil
	case "json":
		return renderJSON(w, r)
	default:
		return fmt.Errorf("unknown diff format %q", format)
	}
}

// ── table ───────────────────────────────────────────────────────────────────

func renderTable(w io.Writer, r *Result) {
	lines := []string{
		fmt.Sprintf("%-13s %s", "Old", r.Old.Source.Target),
		fmt.Sprintf("%-13s %s", "New", r.New.Source.Target),
		fmt.Sprintf("%-13s %d added, %d removed, %d changed, %d unchanged",
			"Components", len(r.Added), len(r.Removed), len(r.Changed), r.Unchanged),
	}
	if r.TestOnlySkipped > 0 {
		lines = append(lines, fmt.Sprintf("%-13s %d test-scoped component(s) skipped (--include-tests to count them)",
			"Test scope", r.TestOnlySkipped))
	}
	// Inside the summary box, above the counts: a reader who takes the numbers
	// as fact has already been misled by the time a footnote arrives.
	if len(r.Drift) > 0 {
		lines = append(lines, "", "⚠ Not comparable")
		for _, d := range r.Drift {
			lines = append(lines, "  "+d)
		}
		lines = append(lines, "  the delta below includes tooling differences, not just code")
	}
	tablew.SummaryBox(w, "AIBOM Diff", lines)

	if r.Empty() {
		fmt.Fprintln(w, "\nNo AI changes.")
		return
	}

	section := func(title string, comps []airom.Component) {
		if len(comps) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s (%d)\n", title, len(comps))
		rows := make([][]string, 0, len(comps))
		for i := range comps {
			c := &comps[i]
			rows = append(rows, []string{
				string(c.Kind), c.Name, dash(optDisplay(c.Version)), dash(optDisplay(c.Provider)),
				confidence(c.Confidence), dash(minLocation(c)),
			})
		}
		tablew.BoxTable(w, []string{"KIND", "NAME", "VERSION", "PROVIDER", "CONF", "LOCATION"}, rows)
	}
	section("Added", r.Added)
	section("Removed", r.Removed)

	if len(r.Changed) > 0 {
		fmt.Fprintf(w, "\nChanged (%d)\n", len(r.Changed))
		var rows [][]string
		for i := range r.Changed {
			ch := &r.Changed[i]
			for j, f := range ch.Fields {
				kind, name := string(ch.Component.Kind), ch.Component.Name
				if j > 0 { // repeat rows read as one component
					kind, name = "", ""
				}
				rows = append(rows, []string{kind, name, f.Field, dash(f.Old), dash(f.New)})
			}
		}
		tablew.BoxTable(w, []string{"KIND", "NAME", "FIELD", "OLD", "NEW"}, rows)
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ── markdown ────────────────────────────────────────────────────────────────

// renderMarkdown emits a PR-comment-ready report: a one-line verdict, then
// one table per section. Deliberately self-contained — it names the targets
// so the comment still reads correctly when detached from the CI run.
func renderMarkdown(w io.Writer, r *Result) {
	fmt.Fprintf(w, "## AIBOM diff — `%s` → `%s`\n\n", mdEscape(r.Old.Source.Target), mdEscape(r.New.Source.Target))
	writeMDDriftNote(w, r)

	if r.Empty() {
		fmt.Fprintf(w, "**No AI changes.** %d component(s) unchanged.\n", r.Unchanged)
		writeMDTestNote(w, r)
		return
	}

	fmt.Fprintf(w, "**%d added · %d removed · %d changed** — %d unchanged.\n",
		len(r.Added), len(r.Removed), len(r.Changed), r.Unchanged)
	writeMDTestNote(w, r)

	section := func(title string, comps []airom.Component) {
		if len(comps) == 0 {
			return
		}
		fmt.Fprintf(w, "\n### %s\n\n", title)
		fmt.Fprintln(w, "| Kind | Name | Version | Provider | Confidence | Evidence |")
		fmt.Fprintln(w, "|---|---|---|---|---|---|")
		for i := range comps {
			c := &comps[i]
			loc := minLocation(c)
			if loc != "" {
				loc = "`" + loc + "`"
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n",
				c.Kind, mdEscape(c.Name), dash(mdEscape(optDisplay(c.Version))),
				dash(mdEscape(optDisplay(c.Provider))), confidence(c.Confidence), dash(mdEscape(loc)))
		}
	}
	section("Added", r.Added)
	section("Removed", r.Removed)

	if len(r.Changed) > 0 {
		fmt.Fprintf(w, "\n### Changed\n\n")
		fmt.Fprintln(w, "| Kind | Name | Change |")
		fmt.Fprintln(w, "|---|---|---|")
		for i := range r.Changed {
			ch := &r.Changed[i]
			for j, f := range ch.Fields {
				kind, name := string(ch.Component.Kind), mdEscape(ch.Component.Name)
				if j > 0 {
					kind, name = "", ""
				}
				fmt.Fprintf(w, "| %s | %s | %s: `%s` → `%s` |\n",
					kind, name, f.Field, dash(mdEscape(f.Old)), dash(mdEscape(f.New)))
			}
		}
	}
}

// writeMDDriftNote leads the comment with the caveat. A PR comment is read by
// someone deciding whether to merge, and "these numbers are not purely your
// change" has to reach them before the numbers do.
func writeMDDriftNote(w io.Writer, r *Result) {
	if len(r.Drift) == 0 {
		return
	}
	fmt.Fprintln(w, "> [!WARNING]")
	fmt.Fprintln(w, "> **These two AIBOMs were produced by different tooling, so this delta is not attributable to the code alone.**")
	for _, d := range r.Drift {
		fmt.Fprintf(w, "> - %s\n", mdEscape(d))
	}
	fmt.Fprintln(w, ">")
	fmt.Fprintln(w, "> Re-scan both sides with the same airom build and ruleset for a comparison that means something.")
	fmt.Fprintln(w)
}

func writeMDTestNote(w io.Writer, r *Result) {
	if r.TestOnlySkipped > 0 {
		fmt.Fprintf(w, "\n_%d test-scoped component(s) not compared (`--include-tests` to count them)._\n", r.TestOnlySkipped)
	}
}

// mdEscape neutralizes the Markdown table delimiter so a value containing a
// pipe cannot break the table layout (same rule as the compliance report).
func mdEscape(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '|' {
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return string(out)
}

// ── json ────────────────────────────────────────────────────────────────────

// docRef identifies one side of the diff for machine consumers.
type docRef struct {
	Path      string    `json:"path"`
	Target    string    `json:"target"`
	Serial    string    `json:"serial"`
	Timestamp time.Time `json:"timestamp"`
}

type jsonSummary struct {
	Added           int `json:"added"`
	Removed         int `json:"removed"`
	Changed         int `json:"changed"`
	Unchanged       int `json:"unchanged"`
	TestOnlySkipped int `json:"testOnlySkipped,omitempty"`
}

type jsonDoc struct {
	Old docRef `json:"old"`
	New docRef `json:"new"`
	// ProvenanceDrift is present only when the two documents came from
	// different tooling. A machine consumer must be able to see that the
	// delta is confounded without re-deriving it from tool metadata.
	ProvenanceDrift []string          `json:"provenanceDrift,omitempty"`
	Summary         jsonSummary       `json:"summary"`
	Added           []airom.Component `json:"added,omitempty"`
	Removed         []airom.Component `json:"removed,omitempty"`
	Changed         []Change          `json:"changed,omitempty"`
}

func renderJSON(w io.Writer, r *Result) error {
	doc := jsonDoc{
		Old:             docRef{Path: r.OldPath, Target: r.Old.Source.Target, Serial: r.Old.Serial, Timestamp: r.Old.Timestamp},
		New:             docRef{Path: r.NewPath, Target: r.New.Source.Target, Serial: r.New.Serial, Timestamp: r.New.Timestamp},
		ProvenanceDrift: r.Drift,
		Summary: jsonSummary{
			Added: len(r.Added), Removed: len(r.Removed), Changed: len(r.Changed),
			Unchanged: r.Unchanged, TestOnlySkipped: r.TestOnlySkipped,
		},
		Added: r.Added, Removed: r.Removed, Changed: r.Changed,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}
