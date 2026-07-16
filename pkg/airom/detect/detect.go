// Package detect is the public detector SDK (ARCHITECTURE.md §6.1): the
// contracts a detector implements, the read-once File it receives, the
// Finding claims it emits, and the selector index that routes files to
// detectors. Stdlib-only by lint (§4) — a third-party detector inherits
// zero transitive dependencies.
//
// Detectors emit claims, never components (invariant P4): identity, dedup,
// merging, and confidence are assembler monopolies, so a detector cannot
// break identity or caching.
package detect

import (
	"context"
	"io/fs"
	"path"
	"strings"
	"time"
)

// Language identifies a source language for selector routing. Values match
// the engine's classifier; the supported analysis set is below.
type Language string

// The supported analysis languages plus the config formats infra detectors
// consume.
const (
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangGo         Language = "go"
	LangJava       Language = "java"
	LangRust       Language = "rust"
	LangCSharp     Language = "csharp"
	LangKotlin     Language = "kotlin"
	LangYAML       Language = "yaml"
	LangJSON       Language = "json"
	LangTOML       Language = "toml"
	LangUnknown    Language = ""
)

// extLanguages maps lowercase extensions to languages — the single source
// of truth the engine's classifier delegates to.
var extLanguages = map[string]Language{
	".py": LangPython, ".pyi": LangPython,
	".js": LangJavaScript, ".mjs": LangJavaScript, ".cjs": LangJavaScript, ".jsx": LangJavaScript,
	".ts": LangTypeScript, ".tsx": LangTypeScript, ".mts": LangTypeScript, ".cts": LangTypeScript,
	".go":   LangGo,
	".java": LangJava,
	".rs":   LangRust,
	".cs":   LangCSharp,
	".kt":   LangKotlin, ".kts": LangKotlin,
	".yaml": LangYAML, ".yml": LangYAML,
	".json": LangJSON,
	".toml": LangTOML,
}

// LanguageOf classifies a file by its path alone (extension-based).
func LanguageOf(p string) Language {
	return extLanguages[strings.ToLower(path.Ext(p))]
}

// Need declares how much of a file a detector consumes — the dispatcher and
// (for stream sources) the spool policy plan around the strongest Need of
// the matched set.
type Need uint8

// The three access levels.
const (
	NeedStat    Need = iota // path + metadata only
	NeedHeader              // the shared 32 KB header sample
	NeedContent             // the single bounded, tee-hashed content read
)

// Magic is a fixed byte signature at a fixed offset, checked against the
// shared header sample — selection costs zero extra I/O.
type Magic struct {
	Offset int
	Bytes  []byte
}

// Selector is a detector's declarative interest (§6.1). The dispatcher
// compiles ALL selectors into one index evaluated once per file —
// O(matches), never O(detectors).
//
// Matching semantics: every SPECIFIED dimension must accept the file (AND
// across dimensions); within a dimension, any entry may match (OR). The
// path dimension is the union of Basenames, Extensions, and PathGlobs. An
// empty dimension is unconstrained. A zero Selector matches every file —
// declare the narrowest selector that covers your fixtures.
type Selector struct {
	Basenames  []string // "requirements.txt", "config.json" — O(1) map hit
	Extensions []string // ".py", ".gguf" — lowercase, with dot — O(1) map hit
	PathGlobs  []string // "**/prompts/**" — kept rare; see Match for glob syntax
	Languages  []Language
	Magic      []Magic
	MaxSize    int64 // reject files larger than this (0 = no size gate)
	Need       Need
}

// FileRef is the classified identity of one file. Path is source-root-
// relative with forward slashes.
type FileRef struct {
	Path     string
	Size     int64
	Mode     fs.FileMode
	ModTime  time.Time
	Language Language
	Binary   bool
	MagicID  string // engine magic-registry ID ("gguf", "zip", …), informational
}

// Detector is the base contract every detector satisfies.
type Detector interface {
	// ID is stable and namespaced ("modelfile/gguf", "rules/openai/…").
	// It becomes the occurrence DetectorID and the SARIF ruleId — treat it
	// like a public API symbol.
	ID() string
	// Version participates in cache keys; bump on ANY behavior change
	// (CI enforces "detector diff ⇒ version bump").
	Version() int
	Selector() Selector
}

// FileDetector runs in phase 1: one file at a time, streaming. Errors (and
// panics) degrade to Unknowns in the output — they never kill the scan
// (invariant P6).
type FileDetector interface {
	Detector
	DetectFile(ctx context.Context, f *File) ([]Finding, error)
}

// ProjectDetector runs in phase 2: cross-file, pull-style over a Resolver,
// with a read-only view of every phase-1 finding. The phase-2 set is flat —
// all project detectors see the same immutable view; there is no
// inter-detector ordering (§3).
type ProjectDetector interface {
	Detector
	DetectProject(ctx context.Context, r Resolver, prior *FindingsView) ([]Finding, error)
}
