package manifest

import (
	"context"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// GoMod detects AI module dependencies declared in a go.mod file.
type GoMod struct{}

// NewGoMod constructs the go.mod detector.
func NewGoMod() *GoMod { return &GoMod{} }

// ID is the stable detector identity.
func (GoMod) ID() string { return "manifest/gomod" }

// Version participates in cache keys; bump on any behavior change.
func (GoMod) Version() int { return 1 }

// Selector routes go.mod files, needing full content.
func (GoMod) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"go.mod"},
		MaxSize:   4 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile parses go.mod with golang.org/x/mod/modfile and emits a finding
// per recognized AI module (each require carries its own source line).
func (d GoMod) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	// Lax parse: tolerate unknown directives from newer go versions.
	mf, err := modfile.Parse(f.Path(), content, nil)
	if err != nil {
		return nil, err // malformed input degrades to an Unknown, never a panic
	}
	var out []detect.Finding
	for _, req := range mf.Require {
		if req == nil {
			continue
		}
		key := trimMajorSuffix(req.Mod.Path)
		p, ok := goCatalog.lookup(key)
		if !ok {
			continue
		}
		line := 0
		if req.Syntax != nil {
			line = req.Syntax.Start.Line
		}
		out = append(out, mkFinding(p, p.emitName(req.Mod.Path), "", "golang", req.Mod.Version, line))
	}
	return out, nil
}

// trimMajorSuffix drops a trailing "/v2", "/v3", … major-version element so a
// versioned module path resolves against the base entry in the catalog.
func trimMajorSuffix(path string) string {
	i := strings.LastIndexByte(path, '/')
	if i < 0 || i+2 >= len(path) || path[i+1] != 'v' {
		return path
	}
	for _, c := range path[i+2:] {
		if c < '0' || c > '9' {
			return path
		}
	}
	return path[:i]
}
