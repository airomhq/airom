// Package ruletest runs rule packs against annotated fixtures — the shared
// engine behind `airom rules test`/`lint` and the embedded-pack CI test
// (docs/rule-schema.md "Fixtures and the lint contract"). Fixtures annotate
// expected matches inline:
//
//	# airom: <rule-id>       ← the NEXT line MUST produce that rule's finding
//	# airom-ok: <rule-id>    ← the NEXT line must NOT
//
// Comment syntax is the host language's ("#" or "//"). The harness also
// enforces the ≥1-positive-and-≥1-negative-fixture-per-rule contract.
package ruletest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Roro1727/airom/internal/ruleengine"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Expectation is one annotated line.
type Expectation struct {
	File     string
	Line     int    // the target line (the annotation's next line)
	RuleID   string // bare rule id, e.g. "openai/model-literal"
	Positive bool   // true = must match, false = must NOT match
}

// Failure is a single mismatch.
type Failure struct {
	File   string
	Line   int
	RuleID string
	Reason string
}

// Report is the outcome of running a pack against its fixtures.
type Report struct {
	Expectations int
	Failures     []Failure
	// RulesMissingPositive / RulesMissingNegative list rule IDs lacking the
	// required fixture coverage (lint contract item 10).
	RulesMissingPositive []string
	RulesMissingNegative []string
}

// OK reports a clean run.
func (r *Report) OK() bool {
	return len(r.Failures) == 0 && len(r.RulesMissingPositive) == 0 && len(r.RulesMissingNegative) == 0
}

var annotationRe = regexp.MustCompile(`(?:#|//)\s*airom(-ok)?:\s*(\S+)`)

// RunPackFile compiles one pack file and runs it against fixtures in
// fixturesDir (typically <pack-dir>/testdata/<pack>/).
func RunPackFile(packPath, fixturesDir string) (*Report, error) {
	rs, err := ruleengine.Load(nil, []string{packPath}, os.ReadFile)
	if err != nil {
		return nil, err
	}
	m, err := ruleengine.Compile(rs)
	if err != nil {
		return nil, err
	}
	return Run(m, fixturesDir)
}

// Run executes a compiled matcher against every fixture under fixturesDir
// and checks the annotations plus per-rule fixture coverage.
func Run(m *ruleengine.Matcher, fixturesDir string) (*Report, error) {
	ruleIDs := map[string]bool{}
	for _, r := range m.Rules() {
		ruleIDs[r.ID] = true
	}

	var fixtures []string
	err := filepath.WalkDir(fixturesDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			fixtures = append(fixtures, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk fixtures %s: %w", fixturesDir, err)
	}
	sort.Strings(fixtures)

	rep := &Report{}
	posSeen := map[string]bool{}
	negSeen := map[string]bool{}
	det := ruleengine.NewDetector(m)

	for _, path := range fixtures {
		data, err := os.ReadFile(path) // #nosec G304 -- fixture path from the pack's own testdata tree
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(fixturesDir, path)
		exps := parseAnnotations(rel, data)
		for _, e := range exps {
			rep.Expectations++
			if e.Positive {
				posSeen[e.RuleID] = true
			} else {
				negSeen[e.RuleID] = true
			}
			if !ruleIDs[e.RuleID] {
				rep.Failures = append(rep.Failures, Failure{
					e.File, e.Line, e.RuleID,
					fmt.Sprintf("fixture references rule %q, which is not in the pack", e.RuleID),
				})
			}
		}

		findings, err := runDetector(det, rel, data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		matched := map[string]map[int]bool{} // ruleID -> set of lines
		for _, f := range findings {
			id := strings.TrimPrefix(f.Occurrence.DetectorID, "rules/")
			if matched[id] == nil {
				matched[id] = map[int]bool{}
			}
			matched[id][f.Occurrence.Location.Line] = true
		}

		for _, e := range exps {
			hit := matched[e.RuleID][e.Line]
			switch {
			case e.Positive && !hit:
				rep.Failures = append(rep.Failures, Failure{e.File, e.Line, e.RuleID, "expected a match, got none"})
			case !e.Positive && hit:
				rep.Failures = append(rep.Failures, Failure{e.File, e.Line, e.RuleID, "expected NO match, but the rule fired"})
			}
		}
	}

	for id := range ruleIDs {
		if !posSeen[id] {
			rep.RulesMissingPositive = append(rep.RulesMissingPositive, id)
		}
		if !negSeen[id] {
			rep.RulesMissingNegative = append(rep.RulesMissingNegative, id)
		}
	}
	sort.Strings(rep.RulesMissingPositive)
	sort.Strings(rep.RulesMissingNegative)
	sort.Slice(rep.Failures, func(i, j int) bool {
		if rep.Failures[i].File != rep.Failures[j].File {
			return rep.Failures[i].File < rep.Failures[j].File
		}
		return rep.Failures[i].Line < rep.Failures[j].Line
	})
	return rep, nil
}

// parseAnnotations extracts expectations (docs/rule-schema.md): a TRAILING
// annotation (code precedes the comment) targets THAT line; a standalone
// annotation targets the next line that is not itself a standalone
// annotation — so stacked annotations all bind to the one code line below
// them.
func parseAnnotations(file string, data []byte) []Expectation {
	lines := strings.Split(string(data), "\n")

	standalone := make([]bool, len(lines)) // annotation alone on its line
	starts := make([]int, len(lines))
	for i, line := range lines {
		loc := annotationRe.FindStringSubmatchIndex(line)
		if loc == nil {
			starts[i] = -1
			continue
		}
		starts[i] = loc[0]
		standalone[i] = strings.TrimSpace(line[:loc[0]]) == ""
	}

	var out []Expectation
	for i, line := range lines {
		if starts[i] < 0 {
			continue
		}
		loc := annotationRe.FindStringSubmatchIndex(line)
		negative := loc[2] >= 0
		ruleID := line[loc[4]:loc[5]]

		target := i + 1 // this line (trailing), 1-based
		if standalone[i] {
			j := i + 1
			for j < len(lines) && standalone[j] {
				j++ // skip stacked annotation lines
			}
			target = j + 1
		}
		out = append(out, Expectation{
			File:     file,
			Line:     target,
			RuleID:   ruleID,
			Positive: !negative,
		})
	}
	return out
}

func runDetector(det *ruleengine.Detector, path string, data []byte) ([]detect.Finding, error) {
	f := detect.NewFile(detect.FileRef{
		Path:     path,
		Size:     int64(len(data)),
		Language: detect.LanguageOf(path),
	}, data, detect.FileProviders{
		Content: func() ([]byte, bool, error) { return data, false, nil },
	})
	return det.DetectFile(context.Background(), f)
}
