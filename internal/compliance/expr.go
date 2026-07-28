package compliance

import (
	"fmt"
	"sort"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
)

// expr is a compiled control-mapping expression: an OR of clauses, each an AND
// of terms. It evaluates to the SET of inventory components it matches — the
// components that become a control's evidence (or counter-evidence).
//
// The grammar deliberately mirrors a SUBSET of the --fail-on grammar
// (internal/app/policy.go): a component-kind ident, "*" (any component), or a
// risk selector ("risk", "risk:<severity>", "risk:<slug>"), joined by "|" (OR)
// and "&" (AND, binding tighter). Confidence comparisons are intentionally
// omitted here. Unifying the two grammars behind one shared evaluator is a
// documented follow-up; until then the two are kept in lockstep by tests.
type expr struct {
	raw     string
	clauses [][]term
}

type termKind int

const (
	termStar     termKind = iota // "*" — any non-root component
	termCompKind                 // a ComponentKind ident
	termRisk                     // "risk" / "risk:<sev>" / "risk:<slug>"
)

type term struct {
	kind     termKind
	compKind airom.ComponentKind
	riskSel  string // for termRisk: "" (any), a severity, or a catalog slug
}

// compile parses a mapping expression, validating every term against the known
// component kinds and risk selectors. A malformed or unknown term is an error,
// so a typo in a framework spec fails at load, never silently matching nothing.
func compile(raw string) (*expr, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty expression")
	}
	e := &expr{raw: trimmed}
	for _, clauseStr := range strings.Split(trimmed, "|") {
		var clause []term
		for _, tokStr := range strings.Split(clauseStr, "&") {
			t, err := parseTerm(strings.TrimSpace(tokStr))
			if err != nil {
				return nil, err
			}
			clause = append(clause, t)
		}
		e.clauses = append(e.clauses, clause)
	}
	return e, nil
}

func parseTerm(s string) (term, error) {
	switch {
	case s == "":
		return term{}, fmt.Errorf("empty term (dangling '&' or '|'?)")
	case s == "*":
		return term{kind: termStar}, nil
	case s == "risk":
		return term{kind: termRisk, riskSel: ""}, nil
	case strings.HasPrefix(s, "risk:"):
		sel := strings.TrimPrefix(s, "risk:")
		if !validRiskSelector(sel) {
			return term{}, fmt.Errorf("unknown risk selector %q (want a severity or a catalog slug)", sel)
		}
		return term{kind: termRisk, riskSel: sel}, nil
	}
	// Otherwise it must be a component kind.
	for _, k := range airom.Kinds() {
		if string(k) == s {
			return term{kind: termCompKind, compKind: k}, nil
		}
	}
	return term{}, fmt.Errorf("unknown term %q (want a component kind, '*', or a risk selector)", s)
}

// validRiskSelector reports whether sel names a known risk severity or slug.
func validRiskSelector(sel string) bool {
	for _, sev := range airom.RiskSeverities() {
		if string(sev) == sel {
			return true
		}
	}
	_, ok := airom.RiskSlugToID(sel)
	return ok
}

// match returns the IDs of the components that satisfy the expression, sorted
// and deduplicated. The application root is never eligible — it is the scan
// target, not a finding, so it never counts as compliance evidence.
//
// Neither is test scaffolding, unless includeTests. A governance report that
// asserts a control is MET and cites `testdata/rag/usage.py` as the evidence is
// worse than one that reports a gap: it claims a practice the shipped system
// does not have. The same cut keeps `--fail-on compliance:gap` consistent with
// every other gate — without it, `--fail-on risk` would ignore a finding that
// `--fail-on compliance:gap` fails the build over, in the same file.
func (e *expr) match(inv *airom.Inventory, includeTests bool) []airom.ID {
	var out []airom.ID
	for i := range inv.Components {
		c := &inv.Components[i]
		if c.Kind == airom.KindApplication {
			continue
		}
		if c.TestOnly && !includeTests {
			continue
		}
		if e.matchesComponent(c) {
			out = append(out, c.ID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// matchesComponent is true iff SOME clause is fully satisfied by c.
func (e *expr) matchesComponent(c *airom.Component) bool {
	for _, clause := range e.clauses {
		if clauseMatches(clause, c) {
			return true
		}
	}
	return false
}

func clauseMatches(clause []term, c *airom.Component) bool {
	for _, t := range clause {
		if !termMatches(t, c) {
			return false
		}
	}
	return len(clause) > 0
}

func termMatches(t term, c *airom.Component) bool {
	switch t.kind {
	case termStar:
		return true
	case termCompKind:
		return c.Kind == t.compKind
	case termRisk:
		return hasRisk(c, t.riskSel)
	}
	return false
}

// hasRisk reports whether c carries a risk matching sel — any risk (sel ""),
// a risk of a given severity, or a risk with a given catalog slug.
func hasRisk(c *airom.Component, sel string) bool {
	for _, r := range c.Risks {
		switch {
		case sel == "":
			return true
		case string(r.Severity) == sel:
			return true
		default:
			if airom.RiskByID(r.ID).Slug == sel {
				return true
			}
		}
	}
	return false
}
