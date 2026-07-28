package app

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/airomhq/airom/internal/compliance"
	"github.com/airomhq/airom/pkg/airom"
)

// Policy is a compiled --fail-on expression: the opt-in CI gate from the
// exit-code contract (docs/cli.md). Grammar, finalized here in Phase 3:
//
//	expr    = clause *( "|" clause )        ; OR of clauses
//	clause  = term   *( "&" term )          ; AND of terms
//	term    = ident | comparison
//	ident   = a ComponentKind ("hosted-llm") or a risk signal ("pickle-risk")
//	comparison = "confidence" op number     ; op: >= <= > < =
//
// "&" binds tighter than "|". Whitespace around tokens is ignored.
// Examples: "hosted-llm", "pickle-risk", "hosted-llm&confidence>=0.9",
// "local-model-file|hosted-llm&confidence>=0.8".
//
// Identifiers are validated against knownIdents at parse time, so an unknown
// term fails loudly instead of silently never matching.
//
// Detector tags are NOT terms. Components record the kind they are, not the
// detector that found them, so a tag has nothing to match against here; the
// grammar once advertised tags and they never worked.
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
	// riskRe matches the artifact-risk selectors: "risk" (any), "risk:high"
	// (by severity), or "risk:pickle-import" (by catalog slug). ':' is outside
	// the ident charset, so these need their own token form.
	riskRe = regexp.MustCompile(`^risk(?::([a-z][a-z0-9-]*))?$`)
	// complianceRe matches the compliance-gap selectors: "compliance" /
	// "compliance:gap" (any gap), "compliance:<framework>" (a gap in that
	// framework), or "compliance:<framework>:<control>" (that control is a gap).
	// The selector carries uppercase and dots (control ids like MAP-2.1), so it
	// gets a permissive capture that parseComplianceSel then validates.
	complianceRe = regexp.MustCompile(`^compliance(?::(.+))?$`)
	// cveRe matches the CVE selectors: "cve" (any) or "cve:<severity>" — a
	// severity THRESHOLD (cve:high fires on high and critical). Requires --cve.
	cveRe = regexp.MustCompile(`^cve(?::([a-z]+))?$`)
	// eolRe matches the model-lifecycle selectors: "eol" (anything retired or
	// deprecated), "eol:retired" / "eol:deprecated" (a state THRESHOLD, so
	// eol:deprecated also fires on retired), or "eol:before:<YYYY-MM-DD>" — the
	// planning gate: "fail if anything in this stack dies before that date".
	// The capture is `.*` so a bare trailing colon ("eol:") reaches
	// validateEOLSel and gets the selector help, rather than falling through to
	// the generic "bad term" message — a trailing colon is the likelier typo.
	eolRe = regexp.MustCompile(`^eol(:(.*))?$`)
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
		// A compliance selector is inventory-level, not per-component, so it
		// cannot be AND-combined with a component term in one clause — a single
		// component can never satisfy both. Reject the mix rather than let it
		// silently never fire. It composes fine across clauses with "|".
		if hasComplianceTerm(conj) && len(conj.terms) > 1 {
			return nil, fmt.Errorf("--fail-on: a compliance selector cannot be combined with '&'; use '|' to OR it with other terms")
		}
		// Lifecycle and CVE selectors describe disjoint populations: EOL applies
		// to hosted models, which carry no purl by design (D9), and CVEs are
		// matched BY purl. No single component can satisfy both, so "&"-ing them
		// is a gate that can only ever pass — almost always a typo'd "|".
		if hasTermPrefix(conj, "eol") && hasTermPrefix(conj, "cve") {
			return nil, fmt.Errorf("--fail-on: eol and cve selectors cannot be combined with '&' — no single component is both a hosted model and a versioned package; use '|' to fail on either")
		}
		p.anyOf = append(p.anyOf, conj)
	}
	return p, nil
}

// hasTermPrefix reports whether a clause contains a selector of the given
// family ("eol", "cve"): the bare word or the word followed by ':'.
func hasTermPrefix(conj conjunction, family string) bool {
	for _, t := range conj.terms {
		if t.Ident == family || strings.HasPrefix(t.Ident, family+":") {
			return true
		}
	}
	return false
}

// hasComplianceTerm reports whether a clause contains a compliance selector.
func hasComplianceTerm(conj conjunction) bool {
	for _, t := range conj.terms {
		if isComplianceIdent(t.Ident) {
			return true
		}
	}
	return false
}

func isComplianceIdent(id string) bool {
	return id == "compliance" || strings.HasPrefix(id, "compliance:")
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
	// Artifact-risk selectors ("risk", "risk:high", "risk:pickle-import").
	if m := riskRe.FindStringSubmatch(s); m != nil {
		if sel := m[1]; sel != "" && !validRiskSelector(sel) {
			return term{}, fmt.Errorf("unknown risk selector %q; want a severity (%s) or a slug (%s)",
				sel, strings.Join(riskSeverityList(), ", "), strings.Join(riskSlugList(), ", "))
		}
		return term{Ident: s}, nil
	}
	// Compliance-gap selectors ("compliance", "compliance:gap",
	// "compliance:<framework>[:<control>]").
	if m := complianceRe.FindStringSubmatch(s); m != nil {
		if _, err := parseComplianceSel(m[1]); err != nil {
			return term{}, err
		}
		return term{Ident: s}, nil
	}
	// CVE selectors ("cve", "cve:<severity>").
	if m := cveRe.FindStringSubmatch(s); m != nil {
		if sev := m[1]; sev != "" && cveSeverityRank(sev) == 0 {
			return term{}, fmt.Errorf("unknown cve severity %q; want critical, high, medium, or low", sev)
		}
		return term{Ident: s}, nil
	}
	// Lifecycle selectors ("eol", "eol:<state>", "eol:before:<date>").
	if m := eolRe.FindStringSubmatch(s); m != nil {
		// m[1] is the whole ":<sel>" (empty for bare "eol"); m[2] is <sel>.
		// They differ only for "eol:", where m[1]=":" and m[2]="" — an empty
		// selector after a colon, which is an error rather than the bare form.
		sel, hadColon := m[2], m[1] != ""
		if hadColon && sel == "" {
			return term{}, fmt.Errorf("empty eol selector; want eol, eol:deprecated, eol:retired, or eol:before:YYYY-MM-DD")
		}
		if err := validateEOLSel(sel); err != nil {
			return term{}, err
		}
		return term{Ident: s}, nil
	}
	// Bare "confidence" is reserved (almost certainly a typo'd comparison),
	// but "confidence-*" and the like remain legal identifiers — the grammar
	// reserves the word, not the prefix.
	if s == "confidence" || (strings.HasPrefix(s, "confidence") && !identRe.MatchString(s)) {
		return term{}, fmt.Errorf("bad confidence comparison %q (want e.g. confidence>=0.9)", s)
	}
	if !identRe.MatchString(s) {
		return term{}, fmt.Errorf("bad term %q (want a kind like hosted-llm, or confidence>=N)", s)
	}
	if !knownIdents[s] {
		return term{}, fmt.Errorf("unknown term %q; want one of: %s, or a comparison like confidence>=0.9",
			s, strings.Join(knownIdentList(), ", "))
	}
	return term{Ident: s}, nil
}

// knownIdents are the identifier terms that can actually match: every
// ComponentKind, plus the risk signals termMatches understands.
//
// Validating against this is the difference between a CI gate and CI theater.
// `--fail-on hosted-llmm` used to parse happily and then never match, so the
// gate passed forever and said nothing — the one place in this CLI where silence
// is dangerous. It is also the contract the rest of the tool already keeps:
// `--select` rejects an unknown detector ID loudly (engine/catalog.go).
//
// KindApplication is deliberately absent: Matches skips the scan root, so
// `--fail-on application` could never fire and admitting it would recreate the
// very bug this map exists to prevent.
var knownIdents = func() map[string]bool {
	m := map[string]bool{"pickle-risk": true}
	for _, k := range airom.Kinds() {
		if k != airom.KindApplication {
			m[string(k)] = true
		}
	}
	return m
}()

// knownIdentList returns the valid identifiers, sorted, for error messages.
func knownIdentList() []string {
	out := make([]string, 0, len(knownIdents))
	for k := range knownIdents {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
		// A compliance clause is inventory-level (its selector was parse-time
		// guaranteed to be the clause's only term), evaluated against the
		// compliance overlay rather than any single component.
		if len(conj.terms) == 1 && isComplianceIdent(conj.terms[0].Ident) {
			if complianceMatches(conj.terms[0].Ident, inv) {
				return true
			}
			continue
		}
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

// complianceSel is a parsed compliance-gap selector. Empty Framework matches
// any framework; empty Control matches any control in the framework.
type complianceSel struct {
	Framework string
	Control   string
}

// parseComplianceSel parses the selector after "compliance:" (or "" for bare
// "compliance"), validating any framework/control names against the embedded
// specs so a typo fails loudly instead of never firing.
func parseComplianceSel(raw string) (complianceSel, error) {
	switch raw {
	case "", "gap":
		return complianceSel{}, nil // any gap, any framework
	}
	fw, control, hasControl := strings.Cut(raw, ":")
	if !compliance.HasFramework(fw) {
		return complianceSel{}, fmt.Errorf("unknown compliance framework %q; valid: %s",
			fw, strings.Join(compliance.IDs(), ", "))
	}
	if hasControl {
		if !compliance.HasControl(fw, control) {
			return complianceSel{}, fmt.Errorf("compliance framework %q has no control %q", fw, control)
		}
	}
	return complianceSel{Framework: fw, Control: control}, nil
}

// complianceMatches reports whether the inventory has a gap matching the
// selector — the gate fires on a GAP (a manual control is not a failure, and a
// met is a pass). Like every --fail-on term it runs over the FULL assembled
// inventory: --min-confidence reshapes the emitted report but never the gate,
// so filtering low-confidence components cannot bypass a CI compliance gate.
func complianceMatches(ident string, inv *airom.Inventory) bool {
	raw := ""
	if strings.HasPrefix(ident, "compliance:") {
		raw = strings.TrimPrefix(ident, "compliance:")
	}
	sel, err := parseComplianceSel(raw)
	if err != nil {
		return false // validated at parse time; unreachable in practice
	}
	for _, fw := range inv.Compliance {
		if sel.Framework != "" && fw.Framework != sel.Framework {
			continue
		}
		for _, c := range fw.Controls {
			if sel.Control != "" && c.ID != sel.Control {
				continue
			}
			if c.State == airom.ControlGap {
				return true
			}
		}
	}
	return false
}

// eolBeforePrefix introduces the date form of the lifecycle selector.
const eolBeforePrefix = "before:"

// validateEOLSel checks an "eol:<sel>" selector at PARSE time, so a typo is a
// usage error rather than a gate that quietly never fires.
//
// "supported" and "unknown" are rejected deliberately: a gate exists to catch
// findings, and neither is one. "unknown" especially — it means the catalog
// says nothing, so a gate on it would fire on every uncurated model in the
// tree and mean nothing at all.
func validateEOLSel(sel string) error {
	switch sel {
	case "": // bare "eol"
		return nil
	case string(airom.EOLRetired), string(airom.EOLDeprecated):
		return nil
	case string(airom.EOLSupported), string(airom.EOLUnknown):
		return fmt.Errorf("eol:%s is not a finding to gate on; use eol, eol:deprecated, eol:retired, or eol:before:YYYY-MM-DD", sel)
	}
	if date, ok := strings.CutPrefix(sel, eolBeforePrefix); ok {
		if _, err := airom.ParseDate(date); err != nil {
			return fmt.Errorf("bad eol:before date %q: %w", date, err)
		}
		return nil
	}
	return fmt.Errorf("unknown eol selector %q; want eol, eol:deprecated, eol:retired, or eol:before:YYYY-MM-DD", sel)
}

// eolTermMatches evaluates a lifecycle selector against one component:
//
//	eol                  any announced retirement (deprecated or retired)
//	eol:retired          already shut down
//	eol:deprecated       a THRESHOLD — deprecated or worse, i.e. also retired
//	eol:before:<date>    shuts down before that date (a retired model, whose
//	                     shutdown is already past, matches any future date)
//
// A model with no lifecycle record never matches: absence is not a finding.
func eolTermMatches(ident string, c *airom.Component) bool {
	e := c.EOL
	if e == nil {
		return false
	}
	sel, _ := strings.CutPrefix(ident, "eol:")
	if ident == "eol" {
		sel = ""
	}

	if date, ok := strings.CutPrefix(sel, eolBeforePrefix); ok {
		if e.Shutdown == nil {
			// A model already retired is before every date, dated or not.
			// An undated DEPRECATION is the only silent case: it cannot answer
			// "does it die before X?" without inventing a deadline the provider
			// never announced.
			return e.State == airom.EOLRetired
		}
		cutoff, err := airom.ParseDate(date)
		if err != nil {
			return false // unreachable: validated at parse time
		}
		// Shutdown ON the cutoff day counts. DeriveEOLState treats the shutdown
		// day as inclusive — on 2026-10-23 the model is already retired — so an
		// exclusive cutoff here would disagree with the rest of the tool on
		// precisely the boundary this gate exists for: "our train leaves on D,
		// fail if anything we ship is dead by then".
		return !e.Shutdown.After(cutoff)
	}

	// State threshold. Bare "eol" uses the deprecated floor, so it means "any
	// announced retirement" and never fires on supported or unknown.
	floor := airom.EOLStateRank(airom.EOLDeprecated)
	if sel != "" {
		floor = airom.EOLStateRank(airom.EOLState(sel))
	}
	return airom.EOLStateRank(e.State) >= floor
}

// cveTermMatches evaluates "cve" (any vuln) or "cve:<severity>" (a vuln at or
// above that severity — a threshold) against one component.
func cveTermMatches(ident string, c *airom.Component) bool {
	threshold := 0 // "cve" — any vulnerability (rank 0 admits every severity)
	if sev, ok := strings.CutPrefix(ident, "cve:"); ok {
		threshold = cveSeverityRank(sev)
	}
	for _, v := range c.Vulnerabilities {
		if cveSeverityRank(string(v.Severity)) >= threshold {
			return true
		}
	}
	return false
}

// cveSeverityRank orders CVE severities for threshold gating; 0 = unknown/none.
func cveSeverityRank(sev string) int {
	switch sev {
	case string(airom.VulnCritical):
		return 4
	case string(airom.VulnHigh):
		return 3
	case string(airom.VulnMedium):
		return 2
	case string(airom.VulnLow):
		return 1
	default:
		return 0
	}
}

// ReferencesCVE reports whether the policy gates on a CVE selector — so config
// validation can reject gating on CVEs that were never fetched (--fail-on cve
// without --cve).
func (p *Policy) ReferencesCVE() bool {
	if p == nil {
		return false
	}
	for _, conj := range p.anyOf {
		for _, t := range conj.terms {
			if t.Ident == "cve" || strings.HasPrefix(t.Ident, "cve:") {
				return true
			}
		}
	}
	return false
}

// ReferencesEOL reports whether the policy gates on a lifecycle selector — so
// config validation can reject gating on an overlay that was turned off, which
// would be a gate that silently never fires.
func (p *Policy) ReferencesEOL() bool {
	if p == nil {
		return false
	}
	for _, conj := range p.anyOf {
		for _, t := range conj.terms {
			if t.Ident == "eol" || strings.HasPrefix(t.Ident, "eol:") {
				return true
			}
		}
	}
	return false
}

// ReferencesCompliance reports whether the policy gates on a compliance
// selector — so config validation can reject gating on compliance that was
// never evaluated (--fail-on compliance:gap without --compliance).
func (p *Policy) ReferencesCompliance() bool {
	if p == nil {
		return false
	}
	for _, conj := range p.anyOf {
		for _, t := range conj.terms {
			if isComplianceIdent(t.Ident) {
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
	if t.Ident == "risk" || strings.HasPrefix(t.Ident, "risk:") {
		return riskTermMatches(t.Ident, c)
	}
	if t.Ident == "cve" || strings.HasPrefix(t.Ident, "cve:") {
		return cveTermMatches(t.Ident, c)
	}
	if t.Ident == "eol" || strings.HasPrefix(t.Ident, "eol:") {
		return eolTermMatches(t.Ident, c)
	}
	// pickle-risk: deprecated alias for the pickle-import risk (back-compat).
	if t.Ident == "pickle-risk" {
		return hasRisk(c, airom.RiskPickleImport)
	}
	return false
}

// riskTermMatches evaluates a "risk" / "risk:<sev>" / "risk:<slug>" selector
// against one component.
func riskTermMatches(ident string, c *airom.Component) bool {
	_, sel, _ := strings.Cut(ident, ":")
	for _, r := range c.Risks {
		switch {
		case sel == "": // "risk" — any
			return true
		case string(r.Severity) == sel: // by severity bucket
			return true
		case airom.RiskByID(r.ID).Slug == sel: // by catalog slug
			return true
		}
	}
	return false
}

// hasRisk reports whether the component carries a risk of the given id.
func hasRisk(c *airom.Component, id airom.RiskID) bool {
	for _, r := range c.Risks {
		if r.ID == id {
			return true
		}
	}
	return false
}

// validRiskSelector reports whether a "risk:<sel>" suffix names a known
// severity bucket or catalog slug.
func validRiskSelector(sel string) bool {
	for _, s := range airom.RiskSeverities() {
		if string(s) == sel {
			return true
		}
	}
	_, ok := airom.RiskSlugToID(sel)
	return ok
}

// riskSeverityList / riskSlugList back the parse-error messages.
func riskSeverityList() []string {
	out := make([]string, 0, len(airom.RiskSeverities()))
	for _, s := range airom.RiskSeverities() {
		out = append(out, string(s))
	}
	return out
}

func riskSlugList() []string {
	var out []string
	for _, m := range airom.RiskCatalog {
		out = append(out, m.Slug)
	}
	sort.Strings(out)
	return out
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
