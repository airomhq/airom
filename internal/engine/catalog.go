package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Tagger is optionally implemented by detectors to declare selection tags
// ("python", "model-file", "image-only", …). Tags feed the Syft-style
// selection expressions (§6.2).
type Tagger interface {
	Tags() []string
}

// Catalog is the explicit detector registry: composed in the composition
// root, never via init() side effects (decision D4). Duplicate IDs panic at
// startup — CI runs the binary, so a collision fails the PR instead of
// silently shadowing (§6.2).
type Catalog struct {
	detectors []detect.Detector
	tags      map[string][]string // id → tags
	ids       map[string]bool
}

// NewCatalog returns an empty catalog.
func NewCatalog() *Catalog {
	return &Catalog{tags: map[string][]string{}, ids: map[string]bool{}}
}

// Add registers a detector with optional extra tags (merged with the
// detector's own Tagger tags). Panics on duplicate or empty IDs.
func (c *Catalog) Add(d detect.Detector, extraTags ...string) {
	id := d.ID()
	if id == "" {
		panic("catalog: detector with empty ID")
	}
	if c.ids[id] {
		panic(fmt.Sprintf("catalog: duplicate detector ID %q", id))
	}
	c.ids[id] = true
	c.detectors = append(c.detectors, d)

	tags := append([]string(nil), extraTags...)
	if tg, ok := d.(Tagger); ok {
		tags = append(tags, tg.Tags()...)
	}
	sort.Strings(tags)
	c.tags[id] = tags
}

// All returns every registered detector in registration order.
func (c *Catalog) All() []detect.Detector { return c.detectors }

// Selection is the resolved detector set for one scan, split by phase, with
// the explanation trail recorded into ScanStats (§6.2 auditability).
type Selection struct {
	File        []detect.FileDetector
	Project     []detect.ProjectDetector
	Explanation []string
}

// Select resolves a Syft-style selection expression: comma-separated
// tokens where a bare token replaces the base set (matching tag or ID),
// "+x" adds, "-x" removes, and "all" selects everything. An empty
// expression selects everything registered.
func (c *Catalog) Select(expr string) (Selection, error) {
	type token struct {
		op   byte // ' ' bare, '+' add, '-' remove
		text string
	}
	var tokens []token
	for _, raw := range strings.Split(expr, ",") {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		switch t[0] {
		case '+', '-':
			if len(t) == 1 {
				return Selection{}, fmt.Errorf("--select: dangling %q", t)
			}
			tokens = append(tokens, token{t[0], t[1:]})
		default:
			tokens = append(tokens, token{' ', t})
		}
	}

	matches := func(id string, t string) bool {
		if t == "all" || t == id {
			return true
		}
		for _, tag := range c.tags[id] {
			if tag == t {
				return true
			}
		}
		return false
	}

	// Validate every token matches something — a typo'd selection must be
	// loud, not a silent no-op (the same contract config keys have).
	// "all" is definitionally valid: it selects everything, including an
	// empty catalog's nothing.
	for _, t := range tokens {
		if t.text == "all" {
			continue
		}
		found := false
		for _, d := range c.detectors {
			if matches(d.ID(), t.text) {
				found = true
				break
			}
		}
		if !found {
			return Selection{}, fmt.Errorf("--select: %q matches no detector ID or tag", t.text)
		}
	}

	selected := map[string]string{} // id → explaining token
	hasBare := false
	for _, t := range tokens {
		if t.op == ' ' {
			hasBare = true
		}
	}
	if !hasBare {
		for _, d := range c.detectors {
			selected[d.ID()] = "default"
		}
	} else {
		for _, t := range tokens {
			if t.op != ' ' {
				continue
			}
			for _, d := range c.detectors {
				if matches(d.ID(), t.text) {
					selected[d.ID()] = t.text
				}
			}
		}
	}
	for _, t := range tokens {
		switch t.op {
		case '+':
			for _, d := range c.detectors {
				if matches(d.ID(), t.text) {
					selected[d.ID()] = "+" + t.text
				}
			}
		case '-':
			for _, d := range c.detectors {
				if matches(d.ID(), t.text) {
					delete(selected, d.ID())
				}
			}
		}
	}

	var sel Selection
	for _, d := range c.detectors { // registration order = deterministic
		why, ok := selected[d.ID()]
		if !ok {
			continue
		}
		switch det := d.(type) {
		case detect.FileDetector:
			sel.File = append(sel.File, det)
		case detect.ProjectDetector:
			sel.Project = append(sel.Project, det)
		default:
			return Selection{}, fmt.Errorf("detector %q implements neither FileDetector nor ProjectDetector", d.ID())
		}
		sel.Explanation = append(sel.Explanation, fmt.Sprintf("%s: selected by %q", d.ID(), why))
	}
	return sel, nil
}
