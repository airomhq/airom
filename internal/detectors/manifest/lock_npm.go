package manifest

import (
	"context"
	"encoding/json"

	"github.com/airomhq/airom/pkg/airom/detect"
)

// PackageLock detects AI dependencies from an npm `package-lock.json`.
//
// package.json declares a range ("^4.20.0"); the lockfile records what the
// resolver actually picked ("4.28.4"). Only the second is a fact, and it is
// the one a vulnerability database can be asked about.
//
// All three lockfile generations are read. v1 nests under `dependencies`, v3
// uses a flat `packages` map keyed by node_modules path, and v2 carries both
// for backward compatibility — reading both keys covers every generation
// without having to trust the declared `lockfileVersion`.
type PackageLock struct{}

// NewPackageLock constructs the npm lockfile detector.
func NewPackageLock() *PackageLock { return &PackageLock{} }

// ID is the stable detector identity.
func (PackageLock) ID() string { return "manifest/npm-lock" }

// Version participates in cache keys; bump on any behavior change.
func (PackageLock) Version() int { return 1 }

// Selector routes package-lock.json and its npm-shrinkwrap twin. The cap is
// generous because a lockfile for a large app is genuinely large.
func (PackageLock) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"package-lock.json", "npm-shrinkwrap.json"},
		MaxSize:   32 << 20,
		Need:      detect.NeedContent,
	}
}

// npmLockV3Entry is one entry of the flat v2/v3 `packages` map.
//
// Its own `dependencies` field is deliberately absent here. In this section
// that field maps names to range STRINGS, while in the v1 section below the
// identically named field maps names to OBJECTS. Declaring one Go type for
// both makes every real lockfile fail to unmarshal.
type npmLockV3Entry struct {
	Version string `json:"version"`
}

// npmLockV1Entry is one entry of the recursive v1 `dependencies` tree.
type npmLockV1Entry struct {
	Version      string                    `json:"version"`
	Dependencies map[string]npmLockV1Entry `json:"dependencies"`
}

type npmLockFile struct {
	Packages     map[string]npmLockV3Entry `json:"packages"`     // v2, v3
	Dependencies map[string]npmLockV1Entry `json:"dependencies"` // v1, v2
}

// DetectFile parses the lockfile and reports the AI packages it resolved.
func (d PackageLock) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	var lf npmLockFile
	if err := json.Unmarshal(content, &lf); err != nil {
		// Surfaced as an Unknown rather than swallowed. Returning nil here
		// reads as "this lockfile holds no AI", which is a different and
		// unverified claim — and it is how a schema mistake in this very
		// detector went unnoticed until a fixture caught it.
		return nil, err
	}

	var pkgs []lockedPkg
	// v2/v3: keys are node_modules paths, so the name needs extracting and the
	// root entry ("") is skipped.
	for key, e := range lf.Packages {
		name := npmPkgName(key)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, lockedPkg{name: name, version: e.Version, line: lineOf(content, `"`+key+`"`)})
	}
	// v1: keys are bare names, nested arbitrarily deep.
	type frame struct {
		name string
		e    npmLockV1Entry
	}
	stack := make([]frame, 0, len(lf.Dependencies))
	for name, e := range lf.Dependencies {
		stack = append(stack, frame{name, e})
	}
	for len(stack) > 0 {
		fr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		pkgs = append(pkgs, lockedPkg{name: fr.name, version: fr.e.Version, line: lineOf(content, `"`+fr.name+`"`)})
		for name, e := range fr.e.Dependencies {
			stack = append(stack, frame{name, e})
		}
	}

	return emitLocked(pkgs, npmCatalog, "npm", lowerName), nil
}
