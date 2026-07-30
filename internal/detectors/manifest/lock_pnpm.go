package manifest

import (
	"context"
	"strings"

	"github.com/airomhq/airom/pkg/airom/detect"
)

// PnpmLock detects AI dependencies from a `pnpm-lock.yaml`.
//
// pnpm encodes the resolved version into the key itself rather than a nested
// field, and the exact spelling has changed across lockfile generations:
//
//	v5   /openai/4.28.4:
//	v6   /openai@4.28.4:
//	v9   openai@4.28.4:
//
// All three are handled by normalizing the leading slash and accepting either
// separator. The file is scanned line-wise rather than YAML-decoded: only the
// keys of the `packages` and `snapshots` blocks are needed, the shape of
// everything else has churned between versions, and a line scan yields exact
// line numbers for free.
type PnpmLock struct{}

// NewPnpmLock constructs the pnpm lockfile detector.
func NewPnpmLock() *PnpmLock { return &PnpmLock{} }

// ID is the stable detector identity.
func (PnpmLock) ID() string { return "manifest/pnpm-lock" }

// Version participates in cache keys; bump on any behavior change.
func (PnpmLock) Version() int { return 1 }

// Selector routes pnpm-lock.yaml.
func (PnpmLock) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"pnpm-lock.yaml", "pnpm-lock.yml"},
		MaxSize:   32 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile reads the keys of the package blocks.
func (d PnpmLock) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}

	var (
		pkgs   []lockedPkg
		inPkgs bool
	)
	for i, raw := range splitLines(content) {
		line := strings.TrimRight(raw, "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			// A top-level key closes any block we were in. `snapshots` is v9's
			// second listing of the same set; reading both is harmless because
			// emitLocked dedupes by name@version.
			key := strings.TrimSuffix(strings.TrimSpace(line), ":")
			inPkgs = key == "packages" || key == "snapshots"
			continue
		}
		if !inPkgs {
			continue
		}
		// Package keys sit one level in. Deeper lines are that entry's fields
		// (resolution, engines, peerDependencies) and must not be read as keys.
		if indentOf(line) != 2 {
			continue
		}
		name, version := pnpmSplitKey(strings.TrimSuffix(strings.TrimSpace(line), ":"))
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, lockedPkg{name: name, version: version, line: i + 1})
	}

	return emitLocked(pkgs, npmCatalog, "npm", lowerName), nil
}

// indentOf counts leading spaces, treating a tab as one column. pnpm writes
// spaces; the tab case only needs to not be miscounted as depth 2.
func indentOf(line string) int {
	n := 0
	for n < len(line) && (line[n] == ' ' || line[n] == '\t') {
		n++
	}
	return n
}

// pnpmSplitKey splits a pnpm package key into name and resolved version,
// accepting every generation's spelling. A peer-dependency suffix — pnpm
// writes `openai@4.28.4(zod@3.23.8)` when a package is resolved per peer set —
// is trimmed, since the parenthesized part describes the context, not this
// package's version.
func pnpmSplitKey(key string) (name, version string) {
	key = strings.Trim(key, `"' `)
	key = strings.TrimPrefix(key, "/")
	if i := strings.IndexByte(key, '('); i >= 0 {
		key = key[:i]
	}
	// v6/v9 use '@' as the separator; v5 used the last '/'.
	if i := strings.LastIndex(key, "@"); i > 0 {
		return key[:i], key[i+1:]
	}
	if i := strings.LastIndex(key, "/"); i > 0 {
		return key[:i], key[i+1:]
	}
	return "", ""
}
