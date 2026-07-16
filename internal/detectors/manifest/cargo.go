package manifest

import (
	"context"
	"strings"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Cargo detects AI dependencies declared in a Rust Cargo.toml under
// [dependencies].
type Cargo struct{}

// NewCargo constructs the Cargo.toml detector.
func NewCargo() *Cargo { return &Cargo{} }

// ID is the stable detector identity.
func (Cargo) ID() string { return "manifest/cargo" }

// Version participates in cache keys; bump on any behavior change.
func (Cargo) Version() int { return 1 }

// Selector routes Cargo.toml files, needing full content.
func (Cargo) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"Cargo.toml"},
		MaxSize:   4 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile scans the [dependencies] table for recognized crates.
func (d Cargo) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	var out []detect.Finding
	section := ""
	for i, raw := range splitLines(content) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = sectionName(line)
			continue
		}
		if section != "dependencies" {
			continue
		}
		key, val, ok := splitKV(line)
		if !ok {
			continue
		}
		name := strings.Trim(key, `"'`)
		if name == "" {
			continue
		}
		p, matched := cargoCatalog.lookup(strings.ToLower(name))
		if !matched {
			continue
		}
		out = append(out, mkFinding(p, p.emitName(name), "", "cargo", poetryVersion(val), i+1))
	}
	return out, nil
}
