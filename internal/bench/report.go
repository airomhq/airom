package bench

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ReportSchemaVersion is the bench.json contract (baselines are this format).
const ReportSchemaVersion = 1

// Report is the aggregate over every corpus entry plus the per-repo detail.
type Report struct {
	SchemaVersion int    `json:"schemaVersion"`
	AiromVersion  string `json:"airomVersion"`
	RulesVersion  string `json:"rulesVersion,omitempty"`
	RulesHash     string `json:"rulesHash,omitempty"`

	Totals *RepoResult   `json:"totals"` // Repo == "TOTAL"
	Repos  []*RepoResult `json:"repos"`
}

// Aggregate folds per-repo results into one report. Deterministic: repos are
// sorted, map keys serialize sorted (encoding/json), and nothing samples time.
func Aggregate(airomVersion, rulesVersion, rulesHash string, repos []*RepoResult) *Report {
	sort.Slice(repos, func(i, j int) bool { return repos[i].Repo < repos[j].Repo })
	tot := &RepoResult{
		Repo:    "TOTAL",
		PerKind: map[string]*PRCell{},
		PerLang: map[string]*PRCell{},
		Bands:   map[string]*BandCell{},
	}
	for _, r := range repos {
		tot.TP += r.TP
		tot.FP += r.FP
		tot.FN += r.FN
		for k, c := range r.PerKind {
			t := cell(tot.PerKind, k)
			t.TP, t.FP, t.FN = t.TP+c.TP, t.FP+c.FP, t.FN+c.FN
		}
		for k, c := range r.PerLang {
			t := cell(tot.PerLang, k)
			t.TP, t.FP, t.FN = t.TP+c.TP, t.FP+c.FP, t.FN+c.FN
		}
		for k, b := range r.Bands {
			t := bandCell(tot.Bands, k)
			t.N, t.Correct = t.N+b.N, t.Correct+b.Correct
		}
		addAttr(&tot.Version, r.Version)
		addAttr(&tot.Provider, r.Provider)
		tot.Location.Valid += r.Location.Valid
		tot.Location.Invalid += r.Location.Invalid
		tot.Location.Ungraded += r.Location.Ungraded
		tot.TrapViolations = append(tot.TrapViolations, prefixAll(r.Repo, r.TrapViolations)...)
		tot.FilesProcessed += r.FilesProcessed
		tot.Unknowns += r.Unknowns
		tot.FilesTruncated += r.FilesTruncated
	}
	sort.Strings(tot.TrapViolations)
	return &Report{
		SchemaVersion: ReportSchemaVersion,
		AiromVersion:  airomVersion,
		RulesVersion:  rulesVersion,
		RulesHash:     rulesHash,
		Totals:        tot,
		Repos:         repos,
	}
}

func addAttr(dst *AttrGrade, src AttrGrade) {
	dst.Exact += src.Exact
	dst.AbsentOK += src.AbsentOK
	dst.Missing += src.Missing
	dst.Wrong += src.Wrong
	dst.Ungraded += src.Ungraded
}

func prefixAll(repo string, ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = repo + ": " + s
	}
	return out
}

// JSON serializes the report; this is the baseline format the gate reads.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Precision and Recall carry their inputs with them everywhere they print.
func prec(tp, fp int) (float64, bool) {
	if tp+fp == 0 {
		return 0, false
	}
	return float64(tp) / float64(tp+fp), true
}

func rec(tp, fn int) (float64, bool) {
	if tp+fn == 0 {
		return 0, false
	}
	return float64(tp) / float64(tp+fn), true
}

func pct(v float64, ok bool) string {
	if !ok {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", v*100)
}

// Markdown renders the human half. Every rate prints beside its counts: a
// rate whose n is hidden is a claim, not a measurement (docs/benchmark.md §6).
func (r *Report) Markdown() string {
	var b strings.Builder
	t := r.Totals
	fmt.Fprintf(&b, "# airom bench — %s", r.AiromVersion)
	if r.RulesVersion != "" {
		fmt.Fprintf(&b, " (rules %s)", r.RulesVersion)
	}
	b.WriteString("\n\n")

	p, pok := prec(t.TP, t.FP)
	rc, rok := rec(t.TP, t.FN)
	fmt.Fprintf(&b, "| | value | n |\n|---|---|---|\n")
	fmt.Fprintf(&b, "| precision | %s | %d reported |\n", pct(p, pok), t.TP+t.FP)
	fmt.Fprintf(&b, "| recall | %s | %d labeled |\n", pct(rc, rok), t.TP+t.FN)
	fmt.Fprintf(&b, "| trap violations | %d | |\n", len(t.TrapViolations))
	fmt.Fprintf(&b, "| wrong versions | %d | %d graded |\n",
		t.Version.Wrong, t.Version.Exact+t.Version.AbsentOK+t.Version.Missing+t.Version.Wrong)
	fmt.Fprintf(&b, "| wrong providers | %d | %d graded |\n",
		t.Provider.Wrong, t.Provider.Exact+t.Provider.Missing+t.Provider.Wrong)
	fmt.Fprintf(&b, "| invalid locations | %d | %d graded |\n",
		t.Location.Invalid, t.Location.Valid+t.Location.Invalid)
	fmt.Fprintf(&b, "| unknowns | %d | %d files |\n", t.Unknowns, t.FilesProcessed)
	fmt.Fprintf(&b, "| truncated reads | %d | %d files |\n\n", t.FilesTruncated, t.FilesProcessed)

	section := func(title string, m map[string]*PRCell) {
		if len(m) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s\n\n| %s | precision | recall | tp | fp | fn |\n|---|---|---|---|---|---|\n",
			title, strings.ToLower(title))
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			c := m[k]
			cp, cpok := prec(c.TP, c.FP)
			cr, crok := rec(c.TP, c.FN)
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d |\n", k, pct(cp, cpok), pct(cr, crok), c.TP, c.FP, c.FN)
		}
		b.WriteString("\n")
	}
	section("Per kind", t.PerKind)
	section("Per language", t.PerLang)

	// The calibration table (§6): nominal band next to observed precision.
	fmt.Fprintf(&b, "## Calibration\n\n| band | n | observed precision |\n|---|---|---|\n")
	for _, band := range []string{"high", "medium", "low"} {
		c := t.Bands[band]
		if c == nil || c.N == 0 {
			fmt.Fprintf(&b, "| %s | 0 | n/a |\n", band)
			continue
		}
		note := ""
		if c.N < 30 {
			note = " (insufficient n)"
		}
		fmt.Fprintf(&b, "| %s | %d | %.1f%%%s |\n", band, c.N, 100*float64(c.Correct)/float64(c.N), note)
	}
	b.WriteString("\n")

	if len(t.TrapViolations) > 0 {
		b.WriteString("## Trap violations\n\n")
		for _, v := range t.TrapViolations {
			fmt.Fprintf(&b, "- %s\n", v)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Repos\n\n| repo | precision | recall | tp | fp | fn | traps |\n|---|---|---|---|---|---|---|\n")
	for _, rr := range r.Repos {
		rp, rpok := prec(rr.TP, rr.FP)
		rrc, rrok := rec(rr.TP, rr.FN)
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d |\n",
			rr.Repo, pct(rp, rpok), pct(rrc, rrok), rr.TP, rr.FP, rr.FN, len(rr.TrapViolations))
	}
	return b.String()
}
