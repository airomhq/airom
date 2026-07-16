package ruleengine

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/cloudflare/ahocorasick"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/ruleengine/lexer"
	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// maxMatchesPerRulePerFile bounds pathological inputs (a generated file with
// a million model literals): beyond the cap the remaining matches are
// dropped and the drop is visible in the finding count. No silent unbounded
// work (invariant P2).
const maxMatchesPerRulePerFile = 200

// region bit masks for grouping rules by their region set.
const (
	regionCode uint8 = 1 << iota
	regionString
)

type compiledRule struct {
	EffectiveRule
	re         *regexp.Regexp
	kind       airom.ComponentKind
	langs      map[detect.Language]bool // nil = all supported
	regionMask uint8
	relations  []compiledRelation
}

type compiledRelation struct {
	typ    airom.RelType
	target TargetTmpl
}

// Matcher is the compiled, immutable ruleset: one Aho–Corasick trie over
// every keyword of every rule, plus per-rule compiled regexes. Safe for
// concurrent use across worker goroutines.
type Matcher struct {
	rules     []compiledRule
	trie      *ahocorasick.Matcher
	kwOwners  [][]int // keyword index → indexes into rules
	langUnion []detect.Language
	hash      string
	paramRes  sync.Map // param name → *regexp.Regexp (lazily compiled, shared)
}

// Compile builds the Matcher from a validated ruleset. Compile-once at
// startup; per-file work is trie + gated regexes only (invariant P3).
func Compile(rs *Ruleset) (*Matcher, error) {
	m := &Matcher{hash: rs.Hash}

	var keywords []string
	kwIndex := map[string]int{} // dedupe: the trie reports each unique needle once,
	// so two rules sharing a keyword must share one dictionary entry
	langSet := map[detect.Language]bool{}

	for _, er := range rs.Rules {
		re, err := regexp.Compile(er.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", er.ID, err) // unreachable post-validate
		}
		cr := compiledRule{
			EffectiveRule: er,
			re:            re,
			kind:          ruleExpressibleKinds[er.Kind],
			regionMask:    regionMaskOf(er.Regions),
		}
		if len(er.Languages) > 0 {
			cr.langs = map[detect.Language]bool{}
			for _, l := range er.Languages {
				cr.langs[supportedLanguages[l]] = true
				langSet[supportedLanguages[l]] = true
			}
		} else {
			for _, l := range supportedLanguages {
				langSet[l] = true
			}
		}
		for _, rel := range er.Relations {
			cr.relations = append(cr.relations, compiledRelation{typ: relTypes[rel.Type], target: rel.Target})
		}
		ruleIdx := len(m.rules)
		m.rules = append(m.rules, cr)

		for _, kw := range er.Keywords {
			idx, ok := kwIndex[kw]
			if !ok {
				idx = len(keywords)
				kwIndex[kw] = idx
				keywords = append(keywords, kw)
				m.kwOwners = append(m.kwOwners, nil)
			}
			m.kwOwners[idx] = append(m.kwOwners[idx], ruleIdx)
		}
	}

	if len(keywords) > 0 {
		m.trie = ahocorasick.NewStringMatcher(keywords)
	}
	for l := range langSet {
		m.langUnion = append(m.langUnion, l)
	}
	sort.Slice(m.langUnion, func(i, j int) bool { return m.langUnion[i] < m.langUnion[j] })
	return m, nil
}

// Hash returns the effective-ruleset content hash (cache-namespace
// ingredient).
func (m *Matcher) Hash() string { return m.hash }

// Empty reports a matcher with no rules (the detector is not registered).
func (m *Matcher) Empty() bool { return len(m.rules) == 0 }

// Rules returns the effective rules (for `airom rules list`).
func (m *Matcher) Rules() []EffectiveRule {
	out := make([]EffectiveRule, len(m.rules))
	for i, r := range m.rules {
		out[i] = r.EffectiveRule
	}
	return out
}

func regionMaskOf(regions []string) uint8 {
	if len(regions) == 0 {
		return regionCode | regionString // default: both
	}
	var mask uint8
	for _, r := range regions {
		switch r {
		case "code":
			mask |= regionCode
		case "string":
			mask |= regionString
		}
	}
	return mask
}

// ── The rule-engine detector ────────────────────────────────────────────────

// Detector executes the compiled ruleset as one FileDetector. Its own ID is
// "ruleengine"; each occurrence carries the per-rule DetectorID
// ("rules/<rule-id>") — the SARIF ruleId contract.
type Detector struct {
	m *Matcher
}

// NewDetector wraps a compiled matcher (explicit constructor injection —
// no globals, decision D4).
func NewDetector(m *Matcher) *Detector { return &Detector{m: m} }

// ID implements detect.Detector.
func (d *Detector) ID() string { return "ruleengine" }

// Version implements detect.Detector. The ruleset CONTENT hash drives cache
// invalidation (self-invalidating rules); this version covers engine
// behavior itself.
func (d *Detector) Version() int { return 1 }

// Tags marks the detector for selection expressions.
func (d *Detector) Tags() []string { return []string{"rules"} }

// Selector implements detect.Detector: the union of every rule's languages.
func (d *Detector) Selector() detect.Selector {
	return detect.Selector{
		Languages: d.m.langUnion,
		Need:      detect.NeedContent,
	}
}

// DetectFile classifies regions, prefilters with the trie, and executes
// only the rules whose keywords hit — within their declared regions
// (docs/rule-schema.md "Compilation and runtime behavior").
func (d *Detector) DetectFile(ctx context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, nil
	}

	lang := f.Ref().Language
	regions := lexer.Classify(classify.Language(lang), content)

	// Keywords are matched over code+string only — comments are never
	// scanned, not even by the prefilter.
	masks := map[uint8][]byte{}
	maskFor := func(mask uint8) []byte {
		if b, ok := masks[mask]; ok {
			return b
		}
		b := lexer.Mask(content, regions, func(t lexer.RegionType) bool {
			switch t {
			case lexer.Code:
				return mask&regionCode != 0
			case lexer.String:
				return mask&regionString != 0
			default:
				return false
			}
		})
		masks[mask] = b
		return b
	}

	kwBuf := maskFor(regionCode | regionString)
	if d.m.trie == nil {
		return nil, nil
	}
	hits := d.m.trie.MatchThreadSafe(kwBuf)
	if len(hits) == 0 {
		return nil, nil
	}

	candidates := map[int]bool{}
	for _, kw := range hits {
		for _, ruleIdx := range d.m.kwOwners[kw] {
			candidates[ruleIdx] = true
		}
	}
	order := make([]int, 0, len(candidates))
	for i := range candidates {
		order = append(order, i)
	}
	sort.Ints(order) // rule order is ID-sorted at load → deterministic output

	var findings []detect.Finding
	for _, ruleIdx := range order {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := &d.m.rules[ruleIdx]
		if r.langs != nil && !r.langs[lang] {
			continue
		}
		buf := maskFor(r.regionMask)
		matches := r.re.FindAllSubmatchIndex(buf, maxMatchesPerRulePerFile)
		for _, match := range matches {
			if fnd, ok := d.finding(r, buf, content, match); ok {
				findings = append(findings, fnd)
			}
		}
	}
	return findings, nil
}

// finding builds one Finding from one regex match.
func (d *Detector) finding(r *compiledRule, buf, content []byte, match []int) (detect.Finding, bool) {
	fields := map[string]string{}
	for gi, name := range r.re.SubexpNames() {
		if name == "" || 2*gi+1 >= len(match) || match[2*gi] < 0 {
			continue
		}
		fields[name] = string(buf[match[2*gi]:match[2*gi+1]])
	}

	name := expand(r.Claim.Name, fields)
	if name == "" {
		return detect.Finding{}, false // non-participating template group: claim nothing
	}

	line, col := lineCol(content, match[0])
	endLine, endCol := lineCol(content, match[1])

	occ := airom.Occurrence{
		Location: airom.Location{
			Line: line, Column: col,
			EndLine: endLine, EndColumn: endCol,
		},
		DetectorID: "rules/" + r.ID,
		Method:     airom.MethodSourceCode,
		Confidence: airom.Confidence(r.Confidence),
		Fields:     fields,
	}

	if r.CaptureParams != nil {
		d.captureParams(r, content, buf, line, occ.Fields)
	}

	claim := detect.ComponentClaim{
		Kind:     r.kind,
		Name:     name,
		Group:    expand(r.Claim.Group, fields),
		Version:  expand(r.Claim.Version, fields),
		Provider: r.Provider,
	}

	var rels []detect.RelationClaim
	for _, cr := range r.relations {
		t := detect.TargetHint{
			Kind:      ruleExpressibleKinds[cr.target.Kind],
			FromField: cr.target.FromField,
			LocalRef:  cr.target.LocalRef,
		}
		if cr.target.Name != "" {
			resolved := expand(cr.target.Name, fields)
			if resolved == "" {
				continue // non-participating group: no hint, no guess
			}
			t.Name = resolved
		}
		rels = append(rels, detect.RelationClaim{Type: cr.typ, Target: t})
	}

	return detect.Finding{Claim: claim, Occurrence: occ, Relations: rels}, true
}

// captureParams scans the ±within_lines window around the match for
// kwarg-style bindings of the declared names, storing them as
// "param.<name>" fields (§9.5; the assembler promotes them only when the
// same occurrence carries a "model" binding).
//
// When a binding name appears multiple times in the window (two calls a few
// lines apart), the occurrence closest to the rule match wins, preferring
// bindings at or after the match line — the call's own kwargs follow the
// call-site match. First-in-window would let a PRECEDING call's model and
// params shadow this call's ("same-call-site capture", D12).
func (d *Detector) captureParams(r *compiledRule, content, buf []byte, matchLine int, fields map[string]string) {
	startLine := matchLine - r.CaptureParams.WithinLines
	if startLine < 1 {
		startLine = 1
	}
	endLine := matchLine + r.CaptureParams.WithinLines
	start, end := lineRange(content, startLine, endLine)
	window := buf[start:end]

	capture := func(name string) string {
		best := nearestBinding(d.paramRe(name), window, startLine, matchLine)
		if best == nil {
			return ""
		}
		return strings.Trim(strings.TrimSpace(string(best)), `"'`)
	}

	// The same-call-site "model" binding is captured implicitly (§9.5):
	// it is what the assembler's param promotion and from_field relation
	// resolution key on.
	if _, has := fields["model"]; !has {
		if val := capture("model"); val != "" {
			fields["model"] = val
		}
	}

	for _, name := range r.CaptureParams.Names {
		if val := capture(name); val != "" {
			fields["param."+name] = val
		}
	}
}

// nearestBinding returns the capture group of the regex match whose line is
// nearest to matchLine (ties prefer at-or-after), or nil.
func nearestBinding(re *regexp.Regexp, window []byte, startLine, matchLine int) []byte {
	matches := re.FindAllSubmatchIndex(window, -1)
	if len(matches) == 0 {
		return nil
	}
	var best []int
	bestScore := int(^uint(0) >> 1)
	for _, m := range matches {
		line := startLine + bytes.Count(window[:m[0]], []byte{'\n'})
		dist := line - matchLine
		before := 0
		if dist < 0 {
			dist, before = -dist, 1
		}
		// nearest line wins; equidistant prefers at-or-after the match.
		score := dist*2 + before
		if score < bestScore {
			bestScore, best = score, m
		}
	}
	if len(best) < 4 || best[2] < 0 {
		return nil
	}
	return window[best[2]:best[3]]
}

// paramRe lazily compiles the kwarg-binding pattern for one param name.
// Shape: name ["']? [:=] value — covering py/js/ts kwargs, dict keys, and
// simple assignments.
func (d *Detector) paramRe(name string) *regexp.Regexp {
	if re, ok := d.m.paramRes.Load(name); ok {
		return re.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`(?m)[\s{,(]["']?` + regexp.QuoteMeta(name) + `["']?\s*[:=]\s*("[^"\n]*"|'[^'\n]*'|[A-Za-z0-9_.\[\]+-]+)`)
	actual, _ := d.m.paramRes.LoadOrStore(name, re)
	return actual.(*regexp.Regexp)
}

// expand substitutes ${group} template variables. Unmatched variables (the
// group didn't participate in this match) yield "".
func expand(tmpl string, fields map[string]string) string {
	if tmpl == "" || !strings.Contains(tmpl, "${") {
		return tmpl
	}
	return templateRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		return fields[m[2:len(m)-1]]
	})
}

// lineCol converts a byte offset into a 1-based line and a 1-based UTF-16
// column (decision D18: SARIF's columnKind).
func lineCol(content []byte, offset int) (line, col int) {
	line = 1
	lineStart := 0
	for i := 0; i < offset && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			lineStart = i + 1
		}
	}
	col = 1
	for i := lineStart; i < offset && i < len(content); {
		r, size := utf8.DecodeRune(content[i:])
		col += utf16.RuneLen(r)
		i += size
	}
	return line, col
}

// lineRange returns the byte range [start, end) covering 1-based lines
// [fromLine, toLine] of content.
func lineRange(content []byte, fromLine, toLine int) (start, end int) {
	line := 1
	start = 0
	for i := 0; i < len(content) && line < fromLine; i++ {
		if content[i] == '\n' {
			line++
			start = i + 1
		}
	}
	end = len(content)
	for i := start; i < len(content); i++ {
		if content[i] == '\n' {
			if line == toLine {
				end = i
				break
			}
			line++
		}
	}
	return start, end
}
