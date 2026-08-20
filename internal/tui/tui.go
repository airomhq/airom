// Package tui holds AIROM's terminal presentation primitives: TTY detection,
// ANSI styling, and the scan progress indicator.
//
// Two rules govern everything here:
//
//  1. **Never stdout.** Progress and styling go to stderr. stdout carries the
//     AIBOM, and invariant P7 requires it to be byte-identical for identical
//     inputs — a spinner on stdout would corrupt `-o json` and break goldens.
//  2. **Degrade to nothing.** Not a terminal, NO_COLOR, dumb TERM, or --quiet:
//     the output must be plain, and progress must not render at all. A scan
//     piped into a file or run in CI produces exactly what it did before.
//
// No third-party dependencies: TTY detection is a stat, styling is ANSI.
package tui

import (
	"os"
	"strings"
)

// IsTTY reports whether f is an interactive terminal.
//
// Implemented with a stat rather than an isatty dependency: a character device
// is a terminal, while a pipe or regular file is not. That is the distinction
// that matters here — if stderr is redirected, we render nothing fancy.
func IsTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ColorEnabled reports whether ANSI styling should be emitted to f.
//
// Honors the NO_COLOR convention (https://no-color.org: any value disables),
// the conventional CLICOLOR_FORCE=1 override, and TERM=dumb.
func ColorEnabled(f *os.File) bool {
	if os.Getenv("CLICOLOR_FORCE") == "1" {
		return true
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if term := os.Getenv("TERM"); term == "dumb" || term == "" {
		return false
	}
	return IsTTY(f)
}

// ── Styling ─────────────────────────────────────────────────────────────────

// Style is an ANSI style that renders as a no-op when color is disabled, so
// call sites never branch on it.
type Style struct {
	codes   string
	enabled bool
}

// ANSI SGR parameters.
const (
	sgrBold   = "1"
	sgrDim    = "2"
	sgrCyan   = "36"
	sgrGreen  = "32"
	sgrYellow = "33"
	sgrRed    = "31"
	sgrWhite  = "37"
	sgrInvert = "7"
)

// Palette is the set of styles for one output stream.
//
// Selected is reverse video, the one style that is not a color: an interactive
// list has to show which row the keyboard is on even where color is off but
// styling is not, and inverting the row is the only marker every terminal
// renders the same way.
type Palette struct {
	Bold, Dim, Accent, Good, Warn, Bad, Heading, Selected Style
}

// NewPalette builds a palette for f, disabled unless color is appropriate.
func NewPalette(f *os.File) Palette {
	on := ColorEnabled(f)
	s := func(codes ...string) Style {
		return Style{codes: strings.Join(codes, ";"), enabled: on}
	}
	return Palette{
		Bold:     s(sgrBold),
		Dim:      s(sgrDim),
		Accent:   s(sgrCyan),
		Good:     s(sgrGreen),
		Warn:     s(sgrYellow),
		Bad:      s(sgrRed),
		Heading:  s(sgrBold, sgrWhite),
		Selected: s(sgrInvert),
	}
}

// S renders v in this style, or unchanged when styling is disabled.
func (st Style) S(v string) string {
	if !st.enabled || st.codes == "" || v == "" {
		return v
	}
	return "\x1b[" + st.codes + "m" + v + "\x1b[0m"
}
