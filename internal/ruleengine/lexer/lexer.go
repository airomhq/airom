package lexer

import "github.com/Roro1727/airom/internal/classify"

// RegionType is the classification of one byte range of source text.
type RegionType uint8

// The three region classes. Comment regions are never scanned by the rule
// engine — not even by the keyword prefilter (docs/rule-schema.md
// "regions"); rules select subsets of {Code, String}.
const (
	Code RegionType = iota
	Comment
	String
)

// String returns the lowercase region-class name (for diagnostics).
func (t RegionType) String() string {
	switch t {
	case Code:
		return "code"
	case Comment:
		return "comment"
	case String:
		return "string"
	default:
		return "invalid"
	}
}

// Region is a half-open byte range [Start, End) of one classified type.
type Region struct {
	Start, End int
	Type       RegionType
}

// Classify splits src into contiguous regions covering [0, len(src)) exactly
// (sorted, non-overlapping, no gaps; adjacent regions may share a type).
// Regions are never empty, so empty input yields no regions. Unknown or
// unsupported languages return one all-Code region. Classify is
// deterministic, single-pass O(len(src)), keeps no global state, and never
// panics on arbitrary bytes (invalid UTF-8 included).
func Classify(lang classify.Language, src []byte) []Region {
	if len(src) == 0 {
		return nil
	}
	cfg := configs[lang]
	if cfg == nil {
		return []Region{{Start: 0, End: len(src), Type: Code}}
	}
	return cfg.classify(src)
}

// Supported reports whether lang has a real lexer (vs the all-Code fallback).
func Supported(lang classify.Language) bool {
	_, ok := configs[lang]
	return ok
}

// Mask returns a copy of src where regions whose type `keep` rejects are
// overwritten with spaces (0x20), EXCEPT newline bytes ('\n', '\r') which are
// preserved so byte offsets AND line/column arithmetic stay valid on the
// masked buffer. len(result) == len(src) always. A nil keep rejects nothing;
// region bounds are clamped to the buffer, so Mask never panics.
func Mask(src []byte, regions []Region, keep func(RegionType) bool) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	if keep == nil {
		return out
	}
	for _, r := range regions {
		if keep(r.Type) {
			continue
		}
		start, end := max(r.Start, 0), min(r.End, len(out))
		for j := start; j < end; j++ {
			if out[j] != '\n' && out[j] != '\r' {
				out[j] = ' '
			}
		}
	}
	return out
}

// ── The shared scanning machine ─────────────────────────────────────────────
//
// One loop, per-language configuration: while in code state the machine
// offers every byte position to an ordered list of token scanners; the first
// scanner that matches consumes a whole Comment or String region and the
// loop resumes after it. Everything no scanner claims is Code.

// tokenFn tries to scan one non-code region beginning exactly at src[i]
// (the caller guarantees i < len(src)). On success it returns the region's
// exclusive end offset and type. A failed attempt must be O(1)-ish (gated
// on the first byte or two); a successful one O(bytes consumed) — together
// they keep classify single-pass O(n).
type tokenFn func(src []byte, i int) (end int, typ RegionType, ok bool)

// langConfig is one language's lexical configuration: an ordered list of
// token scanners tried at every byte position while in code state. First
// match wins, so scanners for longer delimiters (triple quotes, prefixed
// strings) must precede shorter ones sharing a trigger byte.
type langConfig struct {
	tokens []tokenFn
}

// classify runs the machine over src (non-empty), emitting Code filler
// between and around the token regions so the result tiles [0, len(src)).
func (c *langConfig) classify(src []byte) []Region {
	var regions []Region
	codeStart, i := 0, 0
	for i < len(src) {
		matched := false
		for _, tok := range c.tokens {
			end, typ, ok := tok(src, i)
			if !ok {
				continue
			}
			if end > len(src) {
				end = len(src)
			}
			if end <= i { // defensive: a region must consume at least one byte
				continue
			}
			if i > codeStart {
				regions = append(regions, Region{Start: codeStart, End: i, Type: Code})
			}
			regions = append(regions, Region{Start: i, End: end, Type: typ})
			i, codeStart = end, end
			matched = true
			break
		}
		if !matched {
			i++
		}
	}
	if codeStart < len(src) {
		regions = append(regions, Region{Start: codeStart, End: len(src), Type: Code})
	}
	return regions
}

// hasAt reports whether src contains the literal s starting at offset i.
func hasAt(src []byte, i int, s string) bool {
	return i >= 0 && i+len(s) <= len(src) && string(src[i:i+len(s)]) == s
}

// lineComment scans a prefix-to-end-of-line comment. The comment ends
// BEFORE the newline: the '\n' (and '\r') bytes stay Code — the simplest
// choice that keeps newline bytes out of every maskable region.
func lineComment(prefix string) tokenFn {
	return func(src []byte, i int) (int, RegionType, bool) {
		if !hasAt(src, i, prefix) {
			return 0, 0, false
		}
		j := i + len(prefix)
		for j < len(src) && src[j] != '\n' && src[j] != '\r' {
			j++
		}
		return j, Comment, true
	}
}

// blockComment scans a /* ... */ comment; nested enables Rust/Kotlin-style
// depth tracking. Unterminated comments extend to EOF.
func blockComment(nested bool) tokenFn {
	const opener, closer = "/*", "*/"
	return func(src []byte, i int) (int, RegionType, bool) {
		if !hasAt(src, i, opener) {
			return 0, 0, false
		}
		depth := 1
		j := i + len(opener)
		for j < len(src) {
			switch {
			case hasAt(src, j, closer):
				depth--
				j += len(closer)
				if depth == 0 {
					return j, Comment, true
				}
			case nested && hasAt(src, j, opener):
				depth++
				j += len(opener)
			default:
				j++
			}
		}
		return len(src), Comment, true
	}
}

// quoted scans a string or char literal delimited by a single byte.
// escapes: a backslash escapes the next byte (including the delimiter).
// multiline: when false, an unterminated literal ends before the next
// newline byte (which stays Code); when true it runs to the closing
// delimiter or EOF.
func quoted(delim byte, escapes, multiline bool) tokenFn {
	return func(src []byte, i int) (int, RegionType, bool) {
		if src[i] != delim {
			return 0, 0, false
		}
		return scanQuoted(src, i+1, delim, escapes, multiline), String, true
	}
}

// scanQuoted resumes a single-byte-delimited literal at j (just past the
// opening delimiter and any prefix) and returns its exclusive end.
func scanQuoted(src []byte, j int, delim byte, escapes, multiline bool) int {
	for j < len(src) {
		switch {
		case escapes && src[j] == '\\':
			j += 2 // the escaped byte can never close the literal
		case src[j] == delim:
			return j + 1
		case !multiline && (src[j] == '\n' || src[j] == '\r'):
			return j
		default:
			j++
		}
	}
	return len(src)
}

// tripleDQ is the `"""` delimiter shared by Java text blocks, Kotlin raw
// strings, C# raw strings, and Python's double-quoted long strings.
const tripleDQ = `"""`

// tripleQuoted scans a `"""`-delimited multiline literal (Java text blocks
// process escape sequences; Kotlin raw strings do not). Python's
// long-string forms go through pythonString (prefix handling) and C#'s raw
// strings through csharpString (prefix and verbatim disambiguation).
func tripleQuoted(escapes bool) tokenFn {
	return func(src []byte, i int) (int, RegionType, bool) {
		if !hasAt(src, i, tripleDQ) {
			return 0, 0, false
		}
		return scanTriple(src, i+len(tripleDQ), tripleDQ, escapes), String, true
	}
}

// scanTriple resumes a triple-quoted literal at j (just past the opening
// delimiter) and returns its exclusive end (EOF if unterminated).
func scanTriple(src []byte, j int, delim string, escapes bool) int {
	for j < len(src) {
		switch {
		case escapes && src[j] == '\\':
			j += 2
		case hasAt(src, j, delim):
			return j + len(delim)
		default:
			j++
		}
	}
	return len(src)
}
