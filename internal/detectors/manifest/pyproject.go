package manifest

import (
	"context"
	"strings"

	"github.com/airomhq/airom/pkg/airom/detect"
)

// PyProject detects AI dependencies in pyproject.toml, covering both PEP 621
// ([project].dependencies) and Poetry ([tool.poetry.dependencies]).
type PyProject struct{}

// NewPyProject constructs the pyproject.toml detector.
func NewPyProject() *PyProject { return &PyProject{} }

// ID is the stable detector identity.
func (PyProject) ID() string { return "manifest/pypi-pyproject" }

// Version participates in cache keys; bump on any behavior change.
func (PyProject) Version() int { return 2 }

// Selector routes pyproject.toml files, needing full content.
func (PyProject) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"pyproject.toml"},
		MaxSize:   4 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile scans the TOML line by line — enough to read the two dependency
// forms AIROM cares about without a full TOML parser (decision D13).
func (d PyProject) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	lines := splitLines(content)

	var out []detect.Finding
	section := ""
	inProjectDeps := false // inside the PEP 621 dependencies = [ … ] array

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if inProjectDeps {
			for _, dep := range quotedStrings(lines[i]) {
				if fnd, ok := d.pep508(dep, i+1); ok {
					out = append(out, fnd)
				}
			}
			if strings.Contains(stripQuoted(lines[i]), "]") {
				inProjectDeps = false
			}
			continue
		}

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = sectionName(line)
			continue
		}

		switch section {
		case "project":
			if key, val, ok := splitKV(line); ok && key == "dependencies" && strings.Contains(val, "[") {
				for _, dep := range quotedStrings(val) {
					if fnd, ok := d.pep508(dep, i+1); ok {
						out = append(out, fnd)
					}
				}
				if !strings.Contains(stripQuoted(val), "]") {
					inProjectDeps = true
				}
			}
		case "tool.poetry.dependencies":
			if fnd, ok := d.poetry(line, i+1); ok {
				out = append(out, fnd)
			}
		}
	}
	return out, nil
}

// pep508 turns a PEP 621 requirement string into a finding if recognized.
func (PyProject) pep508(dep string, line int) (detect.Finding, bool) {
	name, spec := parsePEP508(dep)
	if name == "" {
		return detect.Finding{}, false
	}
	key := normalizePyPI(name)
	p, ok := pypiCatalog.lookup(key)
	if !ok {
		return detect.Finding{}, false
	}
	return mkFindingSpec(p, p.emitName(key), "", "pypi", spec, true, line), true
}

// poetry turns a "name = spec" Poetry dependency line into a finding.
func (PyProject) poetry(line string, lineNo int) (detect.Finding, bool) {
	key, val, ok := splitKV(line)
	if !ok {
		return detect.Finding{}, false
	}
	name := strings.Trim(key, `"'`)
	if name == "" || name == "python" {
		return detect.Finding{}, false
	}
	norm := normalizePyPI(name)
	p, found := pypiCatalog.lookup(norm)
	if !found {
		return detect.Finding{}, false
	}
	// Poetry expands a bare string to a caret range: "1.40.0" means ^1.40.0,
	// so it is a constraint, not a pin.
	return mkFindingSpec(p, p.emitName(norm), "", "pypi", poetryVersion(val), false, lineNo), true
}

// poetryVersion extracts the RAW version specifier from a Poetry or Cargo
// value: a bare string ("^1.0") or an inline table ({ version = "^1.0", … }).
//
// The operator is deliberately preserved. Stripping it here would erase the
// only signal that separates a pin from a range before the caller can act on
// it — "^1.0" and "1.0" would arrive indistinguishable.
func poetryVersion(val string) string {
	v := strings.TrimSpace(val)
	if strings.HasPrefix(v, "{") {
		if k := strings.Index(v, "version"); k >= 0 {
			return firstQuoted(v[k:])
		}
		return ""
	}
	return firstQuoted(v)
}

// splitKV splits "key = value" at the first '=', trimming surrounding space.
func splitKV(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// sectionName extracts the dotted section path from a "[section]" or
// "[[section]]" header line.
func sectionName(line string) string {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimPrefix(s, "[")
	if i := strings.IndexByte(s, ']'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// stripQuoted removes quoted string literals from a line so structural
// characters (like a closing ']') can be found without matching content
// inside strings (e.g. an "[extras]" group).
func stripQuoted(line string) string {
	var b strings.Builder
	b.Grow(len(line))
	for i := 0; i < len(line); i++ {
		q := line[i]
		if q == '"' || q == '\'' {
			if j := strings.IndexByte(line[i+1:], q); j >= 0 {
				i += j + 1
				continue
			}
		}
		b.WriteByte(line[i])
	}
	return b.String()
}
