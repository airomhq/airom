package lexer

import "github.com/Roro1727/airom/internal/classify"

// configs maps each supported language to its lexical configuration. Built
// once at package init and never mutated afterwards — read-only data, safe
// for concurrent Classify calls.
var configs = buildConfigs()

func buildConfigs() map[classify.Language]*langConfig {
	// JavaScript and TypeScript share one lexical grammar. Regex literals
	// are not modeled (package doc): a // or /* inside one is misread as a
	// comment opener — accepted for v1.
	jsts := &langConfig{tokens: []tokenFn{
		lineComment("//"),
		blockComment(false),
		quoted('"', true, false),
		quoted('\'', true, false),
		quoted('`', true, true), // template literal: whole literal incl ${...} is String
	}}
	return map[classify.Language]*langConfig{
		classify.LangPython: {tokens: []tokenFn{
			lineComment("#"),
			pythonString,
		}},
		classify.LangJavaScript: jsts,
		classify.LangTypeScript: jsts,
		classify.LangGo: {tokens: []tokenFn{
			lineComment("//"),
			blockComment(false),
			quoted('"', true, false),
			quoted('`', false, true),  // raw string: multiline, no escapes
			quoted('\'', true, false), // rune literal
		}},
		classify.LangJava: {tokens: []tokenFn{
			lineComment("//"),
			blockComment(false),
			tripleQuoted(true), // text block (Java 15+); must precede plain "
			quoted('"', true, false),
			quoted('\'', true, false), // char literal
		}},
		classify.LangRust: {tokens: []tokenFn{
			lineComment("//"),
			blockComment(true), // Rust block comments nest
			rustPrefixedString,
			quoted('"', true, true), // Rust strings may span lines
			rustChar,
		}},
		classify.LangCSharp: {tokens: []tokenFn{
			lineComment("//"),
			blockComment(false),
			csharpString,
			quoted('\'', true, false), // char literal
		}},
		classify.LangKotlin: {tokens: []tokenFn{
			lineComment("//"),
			blockComment(true),  // Kotlin block comments nest
			tripleQuoted(false), // raw string: no escapes; must precede plain "
			quoted('"', true, false),
			quoted('\'', true, false), // char literal
		}},
	}
}

// pythonString scans any Python string literal: an optional 1–2 byte prefix
// drawn from r/b/f/u (any case — the scanner deliberately accepts a few
// combinations CPython rejects, such as bf""; those spellings are syntax
// errors anyway, so over-acceptance is harmless), then a single- or
// triple-quoted body. The prefix bytes are part of the String region.
//
// A prefix containing r/R makes the body raw: backslashes are not escapes.
// Note CPython actually still lets a backslash guard the closing quote in
// raw literals (the backslash stays in the value); v1 treats raw as
// strictly no-escapes per the raw-string contract — the divergence ends the
// region one byte early on that corner, never manufactures a comment.
// f-string interpolation braces are NOT broken out: the entire literal is
// String (package doc).
func pythonString(src []byte, i int) (int, RegionType, bool) {
	j, raw := i, false
prefix:
	for j < len(src) && j-i < 2 {
		switch src[j] {
		case 'r', 'R':
			raw = true
		case 'b', 'B', 'f', 'F', 'u', 'U':
			// kind prefixes; only region membership matters here
		default:
			break prefix
		}
		j++
	}
	if j >= len(src) || (src[j] != '\'' && src[j] != '"') {
		return 0, 0, false
	}
	q := src[j]
	delim := tripleDQ
	if q == '\'' {
		delim = "'''"
	}
	if hasAt(src, j, delim) {
		return scanTriple(src, j+len(delim), delim, !raw), String, true
	}
	return scanQuoted(src, j+1, q, !raw, false), String, true
}

// rustPrefixedString scans Rust raw strings r"..." and r#"..."# (up to 8
// #s; no escapes; closed by '"' followed by the same number of #s) plus the
// byte-string forms br#"..."#/br"..." and plain byte strings b"..."
// (escaped, multiline). Plain "..." goes through the shared quoted scanner
// and b'x' byte chars through rustChar (their leading b stays Code —
// harmless for region gating).
func rustPrefixedString(src []byte, i int) (int, RegionType, bool) {
	j := i
	hasB := src[j] == 'b'
	if hasB {
		j++
	}
	if j < len(src) && src[j] == 'r' {
		j++
		hashes := 0
		for j < len(src) && src[j] == '#' && hashes < 8 {
			hashes++
			j++
		}
		if j < len(src) && src[j] == '"' {
			return scanRustRaw(src, j+1, hashes), String, true
		}
		return 0, 0, false
	}
	if hasB && j < len(src) && src[j] == '"' {
		return scanQuoted(src, j+1, '"', true, true), String, true
	}
	return 0, 0, false
}

// scanRustRaw resumes a raw string body just past the opening quote and
// returns the offset past the closing '"' + hashes delimiter (EOF if
// unterminated).
func scanRustRaw(src []byte, j, hashes int) int {
	for j < len(src) {
		if src[j] != '"' {
			j++
			continue
		}
		k, n := j+1, 0
		for k < len(src) && n < hashes && src[k] == '#' {
			n++
			k++
		}
		if n == hashes {
			return k
		}
		j = k // bytes j+1..k-1 are all '#'; none can start a close
	}
	return len(src)
}

// rustChar scans a Rust char literal while leaving lifetimes ('a, 'static,
// '_) as Code. The rule (package doc): a single-quote opens a char literal
// only when followed by an escape sequence, or a single non-quote byte, and
// then a closing quote. The escape arm scans a bounded window — long enough for
// '\u{10FFFF}' — for the close. Multi-byte (non-ASCII) char literals are
// not recognized and stay Code, which is harmless for region gating.
func rustChar(src []byte, i int) (int, RegionType, bool) {
	if src[i] != '\'' || i+1 >= len(src) {
		return 0, 0, false
	}
	j := i + 1
	if src[j] == '\\' {
		// Longest escape, \u{10FFFF}, closes 10 bytes after the backslash.
		limit := min(j+10, len(src)-1)
		for k := j + 2; k <= limit; k++ {
			switch src[k] {
			case '\'':
				return k + 1, String, true
			case '\n':
				return 0, 0, false
			}
		}
		return 0, 0, false
	}
	if src[j] != '\'' && j+1 < len(src) && src[j+1] == '\'' {
		return j + 2, String, true
	}
	return 0, 0, false
}

// csharpString scans every C# string form from its first byte: an optional
// 1–2 byte prefix over $ and @ ($", @", $@", @$", and C# 11's $$"""), then
// a raw string ("""...""", multiline, no escapes), a verbatim body ("" is
// the escaped quote, multiline, no backslash escapes), or a regular escaped
// single-line literal. Interpolated forms classify the whole literal —
// including {...} holes — as String (package doc).
func csharpString(src []byte, i int) (int, RegionType, bool) {
	j, verbatim := i, false
prefix:
	for j < len(src) && j-i < 2 {
		switch src[j] {
		case '@':
			verbatim = true
		case '$':
			// interpolation marker; the whole literal is String either way
		default:
			break prefix
		}
		j++
	}
	if j >= len(src) || src[j] != '"' {
		return 0, 0, false
	}
	switch {
	case verbatim:
		return scanCSharpVerbatim(src, j+1), String, true
	case hasAt(src, j, tripleDQ):
		return scanTriple(src, j+len(tripleDQ), tripleDQ, false), String, true
	default:
		return scanQuoted(src, j+1, '"', true, false), String, true
	}
}

// scanCSharpVerbatim resumes a verbatim string body just past the opening
// quote: "" is an escaped quote, backslashes are literal, newlines are
// allowed. Returns the exclusive end (EOF if unterminated).
func scanCSharpVerbatim(src []byte, j int) int {
	for j < len(src) {
		if src[j] == '"' {
			if j+1 < len(src) && src[j+1] == '"' {
				j += 2
				continue
			}
			return j + 1
		}
		j++
	}
	return len(src)
}
