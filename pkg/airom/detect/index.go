package detect

import (
	"bytes"
	"fmt"
	"path"
	"strings"
)

// Index is the compiled selector index (§6.1): every detector's Selector
// folded into one structure evaluated once per file — O(matches), never
// O(detectors). It is part of the public SDK so the detectortest harness
// routes fixtures through EXACTLY the routing the engine uses.
type Index struct {
	detectors []Detector

	byBasename map[string][]int
	byExt      map[string][]int
	withGlobs  []int // detectors whose path dimension includes globs
	pathless   []int // detectors with no path dimension at all
}

// NewIndex compiles detectors into an index. It rejects duplicate IDs and
// invalid selector globs — the catalog turns these into startup panics so a
// collision fails CI, never silently shadows.
func NewIndex(detectors []Detector) (*Index, error) {
	ix := &Index{
		detectors:  detectors,
		byBasename: make(map[string][]int),
		byExt:      make(map[string][]int),
	}
	seen := make(map[string]int, len(detectors))
	for i, d := range detectors {
		id := d.ID()
		if id == "" {
			return nil, fmt.Errorf("detector #%d has an empty ID", i)
		}
		if j, dup := seen[id]; dup {
			return nil, fmt.Errorf("duplicate detector ID %q (positions %d and %d)", id, j, i)
		}
		seen[id] = i

		sel := d.Selector()
		hasPath := false
		for _, b := range sel.Basenames {
			ix.byBasename[b] = append(ix.byBasename[b], i)
			hasPath = true
		}
		for _, e := range sel.Extensions {
			ix.byExt[strings.ToLower(e)] = append(ix.byExt[strings.ToLower(e)], i)
			hasPath = true
		}
		if len(sel.PathGlobs) > 0 {
			for _, g := range sel.PathGlobs {
				if !ValidateGlob(g) {
					return nil, fmt.Errorf("detector %q: invalid selector glob %q", id, g)
				}
			}
			ix.withGlobs = append(ix.withGlobs, i)
			hasPath = true
		}
		if !hasPath {
			ix.pathless = append(ix.pathless, i)
		}
	}
	return ix, nil
}

// Detectors returns the indexed detectors in registration order.
func (ix *Index) Detectors() []Detector { return ix.detectors }

// Match returns the detectors whose full selector accepts the file, in
// registration order (deterministic; P7). header is the shared sample used
// for Magic checks.
func (ix *Index) Match(ref FileRef, header []byte) []Detector {
	candidates := map[int]struct{}{}

	base := path.Base(ref.Path)
	for _, i := range ix.byBasename[base] {
		candidates[i] = struct{}{}
	}
	if ext := strings.ToLower(path.Ext(ref.Path)); ext != "" {
		for _, i := range ix.byExt[ext] {
			candidates[i] = struct{}{}
		}
	}
	for _, i := range ix.withGlobs {
		if _, already := candidates[i]; already {
			continue
		}
		for _, g := range ix.detectors[i].Selector().PathGlobs {
			if Match(g, ref.Path) {
				candidates[i] = struct{}{}
				break
			}
		}
	}
	for _, i := range ix.pathless {
		candidates[i] = struct{}{}
	}

	var out []Detector
	for i, d := range ix.detectors { // registration order
		if _, ok := candidates[i]; !ok {
			continue
		}
		if selectorRest(d.Selector(), ref, header) {
			out = append(out, d)
		}
	}
	return out
}

// selectorRest evaluates the non-path dimensions: every specified dimension
// must accept (AND); within a dimension any entry may match (OR).
func selectorRest(sel Selector, ref FileRef, header []byte) bool {
	if sel.MaxSize > 0 && ref.Size > sel.MaxSize {
		return false
	}
	if len(sel.Languages) > 0 {
		ok := false
		for _, l := range sel.Languages {
			if ref.Language == l {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(sel.Magic) > 0 {
		ok := false
		for _, m := range sel.Magic {
			end := m.Offset + len(m.Bytes)
			if end <= len(header) && bytes.Equal(header[m.Offset:end], m.Bytes) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
