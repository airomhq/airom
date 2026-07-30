// Package pgext reads PostgreSQL extension metadata off the filesystem.
//
// A vector database is not always a library a project imports. pgvector is a
// server-side extension: it appears in DDL, and otherwise only as files a
// PostgreSQL installation put on disk. A host running pgvector 0.8.1 with five
// HNSW indexes has no requirements.txt, no import, and nothing for a source
// rule to match — but it does have `share/extension/vector.control`, which
// names the extension and its version outright.
package pgext

import (
	"context"
	"regexp"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

const (
	// confControl: the extension's own control file names its version. This is
	// the installation describing itself, so it ranks with installed package
	// metadata rather than with a pattern match.
	confControl = airom.Confidence(0.97)

	// confModule: the loadable module is present but nothing states a version.
	confModule = airom.Confidence(0.8)
)

// aiExtension is a PostgreSQL extension worth putting in an AIBOM.
//
// Keyed by the control file's stem, which is the extension name PostgreSQL
// itself uses. Deliberately short: a host carries dozens of .control files
// (plpgsql, hstore, postgis…) and only the AI ones belong here. Siblings go in
// as they are verified, not as they are remembered.
type aiExtension struct {
	name     string
	provider string
	kind     airom.ComponentKind
}

var aiExtensions = map[string]aiExtension{
	"vector": {"pgvector", "pgvector", airom.KindVectorDB},
}

// Control detects an AI-relevant PostgreSQL extension from its control file.
type Control struct{}

// NewControl constructs the extension-control detector.
func NewControl() *Control { return &Control{} }

// ID is the stable detector identity.
func (Control) ID() string { return "pgext/control" }

// Version participates in cache keys; bump on any behavior change.
func (Control) Version() int { return 1 }

// Selector routes every .control file. A PostgreSQL install has a few dozen,
// each a few hundred bytes, and the stem tells us which matter.
func (Control) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".control"},
		MaxSize:    64 << 10,
		Need:       detect.NeedContent,
	}
}

// defaultVersion matches `default_version = '0.8.1'`, quoted or bare.
var defaultVersion = regexp.MustCompile(`(?mi)^\s*default_version\s*=\s*'?([^'\s#]+)'?`)

// DetectFile reads one extension control file.
func (d Control) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	stem := strings.ToLower(strings.TrimSuffix(f.Base(), ".control"))
	ext, ok := aiExtensions[stem]
	if !ok {
		return nil, nil // an ordinary extension; not this tool's business
	}
	content, err := f.Content()
	if err != nil {
		return nil, err
	}

	version, how := "", "the control file declares no default_version"
	if m := defaultVersion.FindSubmatch(content); m != nil {
		version = string(m[1])
		// default_version is what the INSTALLED FILES provide, which is not
		// necessarily what a given database has loaded: a database created
		// before an upgrade keeps its old version until ALTER EXTENSION runs.
		// Saying which of the two this is keeps the claim honest.
		how = "default_version in the extension control file (the version installed on disk; a database created earlier may still run an older one until ALTER EXTENSION ... UPDATE)"
	}

	return []detect.Finding{{
		Claim: detect.ComponentClaim{
			Kind:     ext.kind,
			Name:     ext.name,
			Version:  version,
			Provider: ext.provider,
		},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Line: lineOfMatch(content, defaultVersion)},
			Method:     airom.MethodConfig,
			Confidence: confControl,
			Snippet:    "PostgreSQL extension installed; version " + how,
		},
	}}, nil
}

// lineOfMatch reports the 1-based line the pattern matched on, or 0 (whole
// file) when it did not match at all.
func lineOfMatch(content []byte, re *regexp.Regexp) int {
	loc := re.FindIndex(content)
	if loc == nil {
		return 0
	}
	return 1 + strings.Count(string(content[:loc[0]]), "\n")
}

// Module detects the loadable module of an AI extension.
//
// Weaker than the control file and kept separate because of it: a file named
// vector.so proves only that something called vector is loadable, and carries
// no version. It earns its place by covering the case the control file cannot —
// a container that ships lib/ without share/ — and it folds into the same
// component when both are present.
type Module struct{}

// NewModule constructs the extension-module detector.
func NewModule() *Module { return &Module{} }

// ID is the stable detector identity.
func (Module) ID() string { return "pgext/module" }

// Version participates in cache keys; bump on any behavior change.
func (Module) Version() int { return 1 }

// Selector is path-anchored rather than name-anchored. "vector.so" on its own
// is far too generic to claim a database extension from; inside a PostgreSQL
// library directory it is unambiguous. The globs cover the layouts the major
// distributions use — RHEL's /usr/pgsql-17/lib, Debian's
// /usr/lib/postgresql/17/lib, and the generic postgresql/ prefix.
func (Module) Selector() detect.Selector {
	return detect.Selector{
		PathGlobs: []string{
			"**/pgsql*/lib/*.so",
			"**/postgresql/**/lib/*.so",
			"**/lib/postgresql/**/*.so",
		},
		Need: detect.NeedStat,
	}
}

// DetectFile reports the extension a loadable module belongs to.
func (d Module) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	stem := strings.ToLower(strings.TrimSuffix(f.Base(), ".so"))
	ext, ok := aiExtensions[stem]
	if !ok {
		return nil, nil
	}
	return []detect.Finding{{
		Claim: detect.ComponentClaim{
			Kind:     ext.kind,
			Name:     ext.name,
			Provider: ext.provider,
		},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Line: 0},
			Method:     airom.MethodFilename,
			Confidence: confModule,
			Snippet:    "PostgreSQL loadable module present; the control file beside it carries the version",
		},
	}}, nil
}
