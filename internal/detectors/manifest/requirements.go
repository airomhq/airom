package manifest

import (
	"context"
	"strings"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Requirements detects AI dependencies declared in pip requirements files
// (requirements.txt, requirements-dev.txt, …).
type Requirements struct{}

// NewRequirements constructs the pip requirements detector.
func NewRequirements() *Requirements { return &Requirements{} }

// ID is the stable detector identity.
func (Requirements) ID() string { return "manifest/pypi-requirements" }

// Version participates in cache keys; bump on any behavior change.
func (Requirements) Version() int { return 1 }

// Selector routes requirements*.txt files, needing full content.
func (Requirements) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"requirements.txt"},
		PathGlobs: []string{"**/requirements*.txt"},
		MaxSize:   4 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile parses a requirements file line by line, emitting one finding
// per recognized AI dependency.
func (d Requirements) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	var out []detect.Finding
	for i, raw := range splitLines(content) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue // blank, comment, or option (-r/-e/--hash)
		}
		// Strip a trailing inline comment (" # …").
		if j := strings.Index(line, " #"); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		name, version := parsePEP508(line)
		if name == "" {
			continue
		}
		key := normalizePyPI(name)
		p, ok := pypiCatalog.lookup(key)
		if !ok {
			continue
		}
		out = append(out, mkFinding(p, p.emitName(key), "", "pypi", version, i+1))
	}
	return out, nil
}
