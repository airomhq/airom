package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// gate thresholds (docs/benchmark.md §5).
const (
	dropTolerance = 0.01 // one point of precision or recall
	kindFloor     = 20   // per-kind gates apply only at >= this many labels
)

// LoadBaseline reads a previously written bench.json.
func LoadBaseline(path string) (*Report, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.SchemaVersion != ReportSchemaVersion {
		return nil, fmt.Errorf("%s: schemaVersion %d, this evaluator reads %d",
			path, r.SchemaVersion, ReportSchemaVersion)
	}
	return &r, nil
}

// Compare applies the gate policy: current against baseline. The returned
// failures are empty when the gate passes. Improvements are reported as
// remarks so the caller can prompt a baseline update, never as failures.
func Compare(baseline, current *Report) (failures, remarks []string) {
	b, c := baseline.Totals, current.Totals

	checkPair := func(scope string, btp, bfp, bfn, ctp, cfp, cfn int) {
		bp, bok := prec(btp, bfp)
		cp, cok := prec(ctp, cfp)
		if bok && cok {
			switch {
			case cp < bp-dropTolerance:
				failures = append(failures, fmt.Sprintf(
					"%s precision dropped %.1f%% -> %.1f%%", scope, bp*100, cp*100))
			case cp > bp+dropTolerance:
				remarks = append(remarks, fmt.Sprintf(
					"%s precision improved %.1f%% -> %.1f%%; update the baseline in this PR", scope, bp*100, cp*100))
			}
		}
		br, bok2 := rec(btp, bfn)
		cr, cok2 := rec(ctp, cfn)
		if bok2 && cok2 {
			switch {
			case cr < br-dropTolerance:
				failures = append(failures, fmt.Sprintf(
					"%s recall dropped %.1f%% -> %.1f%%", scope, br*100, cr*100))
			case cr > br+dropTolerance:
				remarks = append(remarks, fmt.Sprintf(
					"%s recall improved %.1f%% -> %.1f%%; update the baseline in this PR", scope, br*100, cr*100))
			}
		}
	}

	checkPair("overall", b.TP, b.FP, b.FN, c.TP, c.FP, c.FN)
	for kind, bc := range b.PerKind {
		cc := c.PerKind[kind]
		if cc == nil || bc.TP+bc.FN < kindFloor {
			continue // too few labels for the per-kind gate to mean anything
		}
		checkPair("kind "+kind, bc.TP, bc.FP, bc.FN, cc.TP, cc.FP, cc.FN)
	}

	// No thresholds on these two: each trap encodes a lesson already learned,
	// and a wrong version poisons the CVE overlay downstream.
	if len(c.TrapViolations) > len(b.TrapViolations) {
		failures = append(failures, fmt.Sprintf(
			"trap violations increased %d -> %d", len(b.TrapViolations), len(c.TrapViolations)))
	}
	if c.Version.Wrong > b.Version.Wrong {
		failures = append(failures, fmt.Sprintf(
			"wrong-version count increased %d -> %d", b.Version.Wrong, c.Version.Wrong))
	}

	sort.Strings(failures)
	sort.Strings(remarks)
	return failures, remarks
}
