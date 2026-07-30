package manifest

import (
	"context"
	"strings"

	"github.com/airomhq/airom/pkg/airom/detect"
)

// YarnLock detects AI dependencies from a `yarn.lock`.
//
// Both dialects are read by one scanner because they share a shape: an
// unindented header line naming one or more `name@range` specs, followed by an
// indented `version` line holding the resolved version.
//
//	classic (v1)          berry (v2+)
//	"openai@^4.20.0":     "openai@npm:^4.20.0":
//	  version "4.28.4"      version: 4.28.4
//
// The only difference is how the version is quoted, so the parser takes the
// first quoted-or-bare token after the `version` key and accepts either.
type YarnLock struct{}

// NewYarnLock constructs the yarn lockfile detector.
func NewYarnLock() *YarnLock { return &YarnLock{} }

// ID is the stable detector identity.
func (YarnLock) ID() string { return "manifest/yarn-lock" }

// Version participates in cache keys; bump on any behavior change.
func (YarnLock) Version() int { return 1 }

// Selector routes yarn.lock.
func (YarnLock) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"yarn.lock"},
		MaxSize:   32 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile scans header/version pairs.
func (d YarnLock) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}

	var (
		pkgs    []lockedPkg
		pending []string // names from the header block currently open
		hdrLine int
	)
	for i, raw := range splitLines(content) {
		line := strings.TrimRight(raw, "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			// A header: one or more comma-separated specs, ending in ':'.
			pending, hdrLine = nil, i+1
			if !strings.HasSuffix(line, ":") {
				continue
			}
			for _, spec := range strings.Split(strings.TrimSuffix(line, ":"), ",") {
				if n := npmSpecName(spec); n != "" {
					pending = append(pending, n)
				}
			}
			continue
		}
		if len(pending) == 0 {
			continue
		}
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "version")
		if !ok {
			continue
		}
		// Classic writes `version "4.28.4"`, berry writes `version: 4.28.4`.
		// Anything else beginning with "version" (e.g. "versionRange") is not
		// the key and must not be read as one.
		rest = strings.TrimSpace(rest)
		if r, cut := strings.CutPrefix(rest, ":"); cut {
			rest = strings.TrimSpace(r)
		} else if !strings.HasPrefix(rest, `"`) && !strings.HasPrefix(rest, `'`) {
			continue
		}
		version := strings.Trim(rest, `"' `)
		if version == "" {
			continue
		}
		for _, n := range pending {
			pkgs = append(pkgs, lockedPkg{name: n, version: version, line: hdrLine})
		}
		pending = nil
	}

	return emitLocked(pkgs, npmCatalog, "npm", lowerName), nil
}
