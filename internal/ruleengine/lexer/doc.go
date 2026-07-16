// Package lexer splits source text into code / comment / string regions for
// the rule engine (ARCHITECTURE.md §6.4, decision D1; docs/rule-schema.md
// "regions"). These are region classifiers, not parsers: no ASTs, no symbol
// tables — exactly enough lexical context for keyword-gated regex rules to
// never match inside comments, at a cost compatible with the pure-Go,
// CGO_ENABLED=0 distribution story (P8).
//
// Classify covers [0, len(src)) with sorted, non-overlapping, gap-free
// regions for the eight analysis languages (Python, JavaScript, TypeScript,
// Go, Java, Rust, C#, Kotlin); unknown languages get one all-Code region.
// All eight share one config-driven scanning machine (lexer.go) wired by
// per-language configs (langs.go). Go is handled by that same machine
// rather than go/scanner: the engine needs byte-exact region offsets across
// the whole file, and Go's simple lexical grammar is matched exactly by the
// shared machine.
//
// Masking contract: Mask returns a same-length copy of src in which every
// byte of a rejected region is overwritten with a space (0x20) EXCEPT the
// newline bytes '\n' and '\r', which are preserved — so byte offsets AND
// line/column arithmetic computed on the masked buffer remain valid for the
// original.
//
// Documented v1 simplifications (precision is tracked against real ASTs by
// the //go:build oracle CI job, ARCHITECTURE.md §14):
//
//   - JS/TS regex literals are not recognized: a // or /* inside a regex
//     literal is misread as a comment opener.
//   - Interpolated strings (Python f-strings, JS/TS template literals,
//     C# $"..."/$@"...", Kotlin "${...}") classify the ENTIRE literal —
//     including interpolation holes — as String.
//   - Line comments end before the newline: the '\n' (and '\r') bytes
//     themselves are Code.
//   - A Rust single-quote opens a char literal only when a bounded char
//     pattern follows and closes; otherwise it is a lifetime tick and
//     stays Code.
//
// Unterminated strings and comments at EOF extend to EOF with their own
// type; opening and closing delimiters (including string prefixes such as
// Python's rf or C#'s @$) are part of the region they delimit.
package lexer
