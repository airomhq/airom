// Package bench implements the evaluator behind `airom bench`
// (docs/benchmark.md): it scans each corpus entry with the real pipeline,
// matches the result against hand-written truth labels, and reports the
// metric set the release gate consumes.
//
// The package computes; it never judges. Every rate is emitted next to its
// counts, because a rate whose n is hidden is a claim, not a measurement.
package bench

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/airomhq/airom/pkg/airom"
)

// TruthSchemaVersion is the truth.yaml contract this evaluator reads.
const TruthSchemaVersion = 1

// Truth is one corpus entry's ground truth (docs/benchmark.md §4).
type Truth struct {
	SchemaVersion int      `yaml:"schemaVersion"`
	Labeler       string   `yaml:"labeler"`
	Scan          ScanSpec `yaml:"scan"`
	Expected      []Label  `yaml:"expected"`
	Forbidden     []Label  `yaml:"forbidden"`
	Notes         string   `yaml:"notes"`
}

// ScanSpec is reserved for per-repo scan configuration. v1 accepts only an
// empty one: a corpus entry that needs non-default flags is a corpus entry
// whose numbers are not comparable to the rest, and supporting that starts
// as a refusal, not a silent knob.
type ScanSpec struct {
	Args []string `yaml:"args"`
}

// Label is one expected or forbidden component.
type Label struct {
	Kind     string `yaml:"kind"`
	Name     string `yaml:"name"`
	Provider string `yaml:"provider"` // "" = provider is not graded for this label
	// Version grades the matched component's version claim. The zero value is
	// an ASSERTION, not an omission: "" means the honest output is an absent
	// version, and a reported one counts as wrong-version (tri-state
	// discipline, §6.4). Labels that do not want version graded at all say
	// version: "*".
	Version  string     `yaml:"version"`
	Scope    string     `yaml:"scope"`  // "" (default presentation) | "test"
	Reason   string     `yaml:"reason"` // forbidden entries: why this is a trap
	Evidence []Evidence `yaml:"evidence"`
}

// VersionUngraded is the Label.Version sentinel that skips version grading.
const VersionUngraded = "*"

// Evidence is a location the labeler saw the thing at.
type Evidence struct {
	File  string `yaml:"file"`
	Lines []int  `yaml:"lines"` // empty, or [first, last] inclusive
}

// LoadTruth reads and validates one truth.yaml.
func LoadTruth(path string) (*Truth, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- corpus path given by the operator
	if err != nil {
		return nil, err
	}
	var t Truth
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a typo'd key is a broken label, never a no-op
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &t, t.validate(path)
}

func (t *Truth) validate(path string) error {
	var errs []string
	bad := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	if t.SchemaVersion != TruthSchemaVersion {
		bad("schemaVersion = %d, this evaluator reads %d", t.SchemaVersion, TruthSchemaVersion)
	}
	if t.Labeler == "" {
		bad("labeler is required: labels without an accountable author are not ground truth")
	}
	if len(t.Scan.Args) > 0 {
		bad("scan.args is reserved and must be empty in schema 1")
	}
	kinds := map[string]bool{}
	for _, k := range airom.Kinds() {
		kinds[string(k)] = true
	}
	check := func(list []Label, what string, forbidden bool) {
		for i, l := range list {
			at := fmt.Sprintf("%s[%d]", what, i)
			if !kinds[l.Kind] {
				bad("%s: unknown kind %q", at, l.Kind)
			}
			if l.Name == "" {
				bad("%s: name is required", at)
			}
			if l.Scope != "" && l.Scope != "test" {
				bad("%s: scope %q (only \"\" or \"test\")", at, l.Scope)
			}
			if forbidden && l.Reason == "" {
				bad("%s: forbidden entries carry a reason — each trap encodes a lesson", at)
			}
			for j, e := range l.Evidence {
				if e.File == "" {
					bad("%s.evidence[%d]: file is required", at, j)
				}
				if n := len(e.Lines); n != 0 && n != 2 {
					bad("%s.evidence[%d]: lines is empty or [first, last]", at, j)
				}
			}
		}
	}
	check(t.Expected, "expected", false)
	check(t.Forbidden, "forbidden", true)

	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("%s: %s", path, strings.Join(errs, "; "))
	}
	return nil
}

// NormalizeName folds the spelling differences that never distinguish two
// real packages: case, and the -/_/. separator churn. Deliberately ASCII-only
// and length-preserving; a name this cannot fold fails to match, and a missed
// match is a visible FN, never a corrupted one.
func NormalizeName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		case c == '_' || c == '.':
			b.WriteByte('-')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
