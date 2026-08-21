package tui

import (
	"unicode"
	"unicode/utf8"
)

// RuneLen counts runes — for the places a rune count is what is wanted (wrap
// width, tail truncation). Column alignment wants DispWidth instead.
func RuneLen(s string) int { return utf8.RuneCountInString(s) }

// DispWidth approximates the terminal-cell width of s: East-Asian wide/fullwidth
// runes and most emoji take two cells, combining/enclosing marks zero, the rest
// one. It is an approximation (not the full Unicode width tables), but it keeps
// box drawings rectangular for the non-ASCII text a scan can surface — an
// advisory title from OSV, a package name, a path. Pure-ASCII output is
// unaffected, since there DispWidth equals the rune count.
//
// It lives here rather than in one renderer because every aligned surface needs
// the same answer. A second copy measuring in runes is not a cosmetic bug: in
// an interactive table it shifts a row's screen position away from where the
// click handler believes it is, and the button applies to the wrong row.
func DispWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case r == 0:
		case unicode.In(r, unicode.Mn, unicode.Me): // combining / enclosing marks
		case isWide(r):
			w += 2
		default:
			w++
		}
	}
	return w
}

// isWide reports whether r occupies two terminal cells (CJK, Hangul, Kana,
// fullwidth forms, and the common emoji/symbol blocks).
func isWide(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0x303E,   // CJK radicals … Kangxi
		r >= 0x3041 && r <= 0x33FF,   // Hiragana … CJK compat
		r >= 0x3400 && r <= 0x4DBF,   // CJK Ext A
		r >= 0x4E00 && r <= 0x9FFF,   // CJK Unified
		r >= 0xA000 && r <= 0xA4CF,   // Yi
		r >= 0xAC00 && r <= 0xD7A3,   // Hangul syllables
		r >= 0xF900 && r <= 0xFAFF,   // CJK compat ideographs
		r >= 0xFE30 && r <= 0xFE4F,   // CJK compat forms
		r >= 0xFF00 && r <= 0xFF60,   // Fullwidth forms
		r >= 0xFFE0 && r <= 0xFFE6,   // Fullwidth signs
		r >= 0x1F300 && r <= 0x1FAFF, // emoji & pictographs
		r >= 0x20000 && r <= 0x3FFFD: // CJK Ext B+
		return true
	}
	return false
}
