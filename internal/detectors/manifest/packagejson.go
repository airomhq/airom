package manifest

import (
	"context"
	"strings"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// PackageJSON detects AI dependencies declared in an npm package.json, across
// both dependencies and devDependencies.
type PackageJSON struct{}

// NewPackageJSON constructs the npm package.json detector.
func NewPackageJSON() *PackageJSON { return &PackageJSON{} }

// ID is the stable detector identity.
func (PackageJSON) ID() string { return "manifest/npm" }

// Version participates in cache keys; bump on any behavior change.
func (PackageJSON) Version() int { return 1 }

// Selector routes package.json files, needing full content.
func (PackageJSON) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"package.json"},
		MaxSize:   8 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile locates the dependency objects by brace tracking (so lines are
// exact) and matches each declared package against the npm catalog.
func (d PackageJSON) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	lines := splitLines(content)

	var out []detect.Finding
	for _, section := range []string{"dependencies", "devDependencies"} {
		start, end := objectRange(lines, section)
		if start == 0 {
			continue
		}
		for i := start; i < end; i++ { // exclude the "…": { opener; include inner lines
			qs := quotedStrings(lines[i])
			if len(qs) < 2 || qs[0] == section {
				continue
			}
			name, spec := qs[0], qs[1]
			p, ok := npmCatalog.lookup(strings.ToLower(name))
			if !ok {
				continue
			}
			out = append(out, mkFinding(p, p.emitName(name), "", "npm", cleanVersion(spec), i+1))
		}
	}
	return out, nil
}

// objectRange returns the 1-based line span [start, end] of the JSON object
// value of the given top-level key: start is the key's line, end is the line
// of its matching closing brace. Returns 0,0 when the key is absent.
func objectRange(lines []string, key string) (start, end int) {
	target := `"` + key + `"`
	for i := 0; i < len(lines); i++ {
		idx := strings.Index(lines[i], target)
		if idx < 0 {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(lines[i][idx+len(target):]), ":") {
			continue
		}
		depth := 0
		started := false
		for j := i; j < len(lines); j++ {
			code := stripQuoted(lines[j])
			for k := 0; k < len(code); k++ {
				switch code[k] {
				case '{':
					depth++
					started = true
				case '}':
					depth--
				}
			}
			if started && depth == 0 {
				return i + 1, j + 1
			}
		}
		return i + 1, len(lines)
	}
	return 0, 0
}
