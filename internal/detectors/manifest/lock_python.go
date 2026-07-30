package manifest

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/airomhq/airom/pkg/airom/detect"
)

// PoetryLock detects AI dependencies from a `poetry.lock` or a `uv.lock`.
//
// The two tools share a lockfile shape — an array of TOML `[[package]]`
// tables, each leading with `name` and `version` — so one parser covers both:
//
//	[[package]]
//	name = "openai"
//	version = "1.40.0"
//
// Parsed line-wise, matching how pyproject.toml is read in this package rather
// than pulling in a TOML dependency. The critical rule is that collection
// stops at the next line opening a table: poetry follows each package with a
// `[package.dependencies]` sub-table whose keys are themselves package names,
// and reading one of those as the block's `name` would misreport the package.
type PoetryLock struct{}

// NewPoetryLock constructs the poetry/uv lockfile detector.
func NewPoetryLock() *PoetryLock { return &PoetryLock{} }

// ID is the stable detector identity.
func (PoetryLock) ID() string { return "manifest/pypi-lock" }

// Version participates in cache keys; bump on any behavior change.
func (PoetryLock) Version() int { return 1 }

// Selector routes the two TOML lockfiles.
func (PoetryLock) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"poetry.lock", "uv.lock"},
		MaxSize:   32 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile walks the [[package]] blocks.
func (d PoetryLock) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}

	var (
		pkgs    []lockedPkg
		cur     lockedPkg
		inBlock bool
	)
	flush := func() {
		if inBlock && cur.name != "" {
			pkgs = append(pkgs, cur)
		}
		cur, inBlock = lockedPkg{}, false
	}
	for i, raw := range splitLines(content) {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			// Any table header closes the current block — including
			// [package.dependencies], whose keys are other packages' names.
			flush()
			if strings.HasPrefix(line, "[[package]]") {
				inBlock, cur = true, lockedPkg{line: i + 1}
			}
			continue
		}
		if !inBlock {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "name":
			if cur.name == "" {
				cur.name = value
			}
		case "version":
			if cur.version == "" {
				cur.version = value
			}
		}
	}
	flush()

	return emitLocked(pkgs, pypiCatalog, "pypi", normalizePyPI), nil
}

// PipfileLock detects AI dependencies from a `Pipfile.lock`.
//
// pipenv writes JSON, with each package's version as an exact `==` pin — a
// resolved fact despite the operator, which is why cleanVersion is the right
// reader for it here and a misreading elsewhere.
type PipfileLock struct{}

// NewPipfileLock constructs the pipenv lockfile detector.
func NewPipfileLock() *PipfileLock { return &PipfileLock{} }

// ID is the stable detector identity.
func (PipfileLock) ID() string { return "manifest/pipfile-lock" }

// Version participates in cache keys; bump on any behavior change.
func (PipfileLock) Version() int { return 1 }

// Selector routes Pipfile.lock.
func (PipfileLock) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"Pipfile.lock"},
		MaxSize:   32 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile reads the default and develop sections.
func (d PipfileLock) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	var lf struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(content, &lf); err != nil {
		return nil, err // an Unknown, not a silent "no AI here"
	}

	var pkgs []lockedPkg
	for _, section := range []map[string]struct {
		Version string `json:"version"`
	}{lf.Default, lf.Develop} {
		for name, e := range section {
			pkgs = append(pkgs, lockedPkg{
				name:    name,
				version: cleanVersion(e.Version),
				line:    lineOf(content, `"`+name+`"`),
			})
		}
	}

	return emitLocked(pkgs, pypiCatalog, "pypi", normalizePyPI), nil
}
