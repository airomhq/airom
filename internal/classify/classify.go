// Package classify implements file classification (ARCHITECTURE.md §3, §4):
// language identification from paths, binary sniffing over the shared header
// sample, and the magic-byte registry that routes model files to their
// header parsers. Classification is the "decide before you read" gate
// (invariant P3): path and header eliminate most files before any full
// content read.
package classify

import (
	"bytes"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
)

// Language identifies the source language of a file for detector routing
// (the eight supported analysis languages, plus config formats the infra
// detectors consume).
type Language string

// The eight analysis languages plus the config formats infra detectors
// consume; LangUnknown routes to language-agnostic detectors only.
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

// extLanguages maps lowercase extensions to languages.
var extLanguages = map[string]Language{
	".py":   LangPython,
	".pyi":  LangPython,
	".js":   LangJavaScript,
	".mjs":  LangJavaScript,
	".cjs":  LangJavaScript,
	".jsx":  LangJavaScript,
	".ts":   LangTypeScript,
	".tsx":  LangTypeScript,
	".mts":  LangTypeScript,
	".cts":  LangTypeScript,
	".go":   LangGo,
	".java": LangJava,
	".rs":   LangRust,
	".cs":   LangCSharp,
	".kt":   LangKotlin,
	".kts":  LangKotlin,
	".yaml": LangYAML,
	".yml":  LangYAML,
	".json": LangJSON,
	".toml": LangTOML,
}

// LanguageOf classifies a file by its path alone (extension; cheap enough
// for the walker). Content-based refinement is a detector concern.
func LanguageOf(path string) Language {
	return extLanguages[strings.ToLower(filepath.Ext(path))]
}

// Magic is one entry in the magic-byte registry: fixed bytes at a fixed
// offset within the header sample. Exact layouts per format are documented
// in the modelfile detectors (Phase 6); the registry only ROUTES — parsers
// verify.
type Magic struct {
	ID     string // stable id detectors select on: "gguf", "zip", ...
	Offset int
	Bytes  []byte
}

// builtinMagics is the ordered registry (first match wins; more specific
// entries precede generic ones).
var builtinMagics = []Magic{
	{ID: "gguf", Offset: 0, Bytes: []byte("GGUF")},
	{ID: "hdf5", Offset: 0, Bytes: []byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'}},
	{ID: "tflite", Offset: 4, Bytes: []byte("TFL3")},
	{ID: "zip", Offset: 0, Bytes: []byte{'P', 'K', 0x03, 0x04}}, // torch .pt/.pth are zips
	{ID: "onnx-protobuf", Offset: 0, Bytes: []byte{0x08}},       // weak; parser verifies
	{ID: "pickle", Offset: 0, Bytes: []byte{0x80}},              // pickle protocol marker; parser verifies
}

// MatchMagic returns the registry ID matching the header sample, or "".
// Weak single-byte signatures are ordered last so specific formats win.
func MatchMagic(header []byte) string {
	for _, m := range builtinMagics {
		end := m.Offset + len(m.Bytes)
		if end <= len(header) && bytes.Equal(header[m.Offset:end], m.Bytes) {
			return m.ID
		}
	}
	return ""
}

// binarySniffLen bounds the NUL scan (git's heuristic: a NUL byte in the
// first 8 KB means binary).
const binarySniffLen = 8 * 1024

// IsBinary reports whether the header sample looks like binary content.
func IsBinary(header []byte) bool {
	n := len(header)
	if n > binarySniffLen {
		n = binarySniffLen
	}
	return bytes.IndexByte(header[:n], 0) >= 0
}

// FileRef is the classified identity of one file as it flows through the
// pipeline. Path is always source-root-relative with forward slashes.
// Language is filled by the walker (path-based); Binary and MagicID are
// filled worker-side once the header sample exists.
type FileRef struct {
	Path     string
	Size     int64
	Mode     fs.FileMode
	ModTime  time.Time
	Language Language
	Binary   bool
	MagicID  string
}
