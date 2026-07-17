package app

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Roro1727/airom/pkg/airom"
)

// Policy is a compiled --fail-on expression: the opt-in CI gate from the
// exit-code contract (docs/cli.md). Grammar, finalized here in Phase 3:
//
//	expr    = clause *( "|" clause )        ; OR of clauses
//	clause  = term   *( "&" term )          ; AND of terms
//	term    = ident | comparison
//	ident   = lowercase kebab identifier    ; a ComponentKind ("hosted-llm"),
//	                                        ; detector tag, or risk signal
//	                                        ; ("pickle-risk")
//	comparison = "confidence" op number     ; op: >= <= > < =
//
// "&" binds tighter than "|". Whitespace around tokens is ignored.
// Examples: "hosted-llm", "pickle-risk", "hosted-llm&confidence>=0.9",
// "local-model-file|hosted-llm&confidence>=0.8".
//
// Identifier terms are validated syntactically here; semantic validation
// against the ComponentKind enum and detector tags happens when the domain
// model lands (Phase 5), so an unknown kind fails loudly at parse time then
// rather than silently never matching. Evaluation against an assembled
// Inventory also lands in Phase 5 alongside the domain types.
type Policy struct {
	raw   string
	anyOf []conjunction
}

type conjunction struct {
	terms []term
}

// term is either an identifier (Ident != "") or a confidence comparison
// (Cmp != nil) — never both.
type term struct {
	Ident string
	Cmp   *confidenceCmp
}

type confidenceCmp struct {
	Op    string // one of >= <= > < =
	Value float64
}

var (
	identRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	cmpRe   = regexp.MustCompile(`^confidence\s*(>=|<=|>|<|=)\s*([0-9.]+)$`)
)

// MatchAny is the policy used when --exit-code is set without --fail-on:
// "fail on any component" (docs/cli.md).
func MatchAny() *Policy {
	return &Policy{raw: "*", anyOf: []conjunction{{}}}
}

// ParsePolicy compiles a --fail-on expression. An empty expression is an
// error — callers represent "no policy" as a nil *Policy instead.
func ParsePolicy(expr string) (*Policy, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return nil, fmt.Errorf("--fail-on: empty expression")
	}
	p := &Policy{raw: trimmed}
	for _, clause := range strings.Split(trimmed, "|") {
		var conj conjunction
		for _, raw := range strings.Split(clause, "&") {
			t, err := parseTerm(raw)
			if err != nil {
				return nil, fmt.Errorf("--fail-on: %w", err)
			}
			conj.terms = append(conj.terms, t)
		}
		p.anyOf = append(p.anyOf, conj)
	}
	return p, nil
}

func parseTerm(raw string) (term, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return term{}, fmt.Errorf("empty term (dangling '&' or '|'?)")
	}
	if m := cmpRe.FindStringSubmatch(s); m != nil {
		v, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			return term{}, fmt.Errorf("bad confidence value %q: %w", m[2], err)
		}
		if v < 0 || v > 1 {
			return term{}, fmt.Errorf("confidence bound %v outside [0,1]", v)
		}
		return term{Cmp: &confidenceCmp{Op: m[1], Value: v}}, nil
	}
	// Bare "confidence" is reserved (almost certainly a typo'd comparison),
	// but "confidence-*" and the like remain legal identifiers — the grammar
	// reserves the word, not the prefix.
	if s == "confidence" || (strings.HasPrefix(s, "confidence") && !identRe.MatchString(s)) {
		return term{}, fmt.Errorf("bad confidence comparison %q (want e.g. confidence>=0.9)", s)
	}
	if !identRe.MatchString(s) {
		return term{}, fmt.Errorf("bad term %q (want a kind/tag like hosted-llm, or confidence>=N)", s)
	}
	return term{Ident: s}, nil
}

// String returns the original, trimmed expression.
func (p *Policy) String() string { return p.raw }

// Matches reports whether the assembled inventory trips the gate. The
// expression is an OR of conjunctions; a conjunction matches iff a SINGLE
// component satisfies all of its terms — so "hosted-llm&confidence>=0.9" means
// "some hosted-llm component has confidence >= 0.9", not "some hosted-llm
// exists AND some (other) high-confidence component exists". The empty
// conjunction (MatchAny, from --exit-code without --fail-on) matches iff the
// inventory has at least one discovered component (the application root does
// not count — it is the scan target, not a finding).
//
// Identifier terms match a ComponentKind ("hosted-llm") or the "pickle-risk"
// signal (a component whose static pickle scan flagged a dangerous global). An
// identifier matching no kind and no known signal simply never matches.
func (p *Policy) Matches(inv *airom.Inventory) bool {
	if p == nil || inv == nil {
		return false
	}
	for _, conj := range p.anyOf {
		for i := range inv.Components {
			c := &inv.Components[i]
			if c.Kind == airom.KindApplication {
				continue
			}
			if conjunctionMatches(conj, c) {
				return true
			}
		}
	}
	return false
}

// conjunctionMatches reports whether one component satisfies every term. An
// empty term list (MatchAny) is vacuously true, so any non-root component
// trips it.
func conjunctionMatches(conj conjunction, c *airom.Component) bool {
	for _, t := range conj.terms {
		if !termMatches(t, c) {
			return false
		}
	}
	return true
}

func termMatches(t term, c *airom.Component) bool {
	if t.Cmp != nil {
		return compareConfidence(float64(c.Confidence), t.Cmp)
	}
	if t.Ident == string(c.Kind) {
		return true
	}
	if t.Ident == "pickle-risk" {
		return c.Model != nil && c.Model.PickleRisk != nil && len(c.Model.PickleRisk.Globals) > 0
	}
	return false
}

func compareConfidence(v float64, cmp *confidenceCmp) bool {
	switch cmp.Op {
	case ">=":
		return v >= cmp.Value
	case "<=":
		return v <= cmp.Value
	case ">":
		return v > cmp.Value
	case "<":
		return v < cmp.Value
	case "=":
		return v == cmp.Value
	}
	return false
}
