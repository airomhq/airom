package tui

import "testing"

// TestDispWidth pins the measurement every aligned surface depends on. The
// table writer and the interactive fix table both size columns with it, and in
// the interactive one a wrong answer is not cosmetic: a row measured short
// wraps, and every row below it stops sitting where the click handler computes.
func TestDispWidth(t *testing.T) {
	cases := []struct {
		s    string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"日本語", 6}, // CJK: two cells each
		{"a日b", 4},
		{"🚀", 2},   // emoji
		{"한국어", 6}, // Hangul syllables
		{"ｱｲｳ", 3}, // halfwidth kana stay one cell
		{"ＡＢ", 4},  // fullwidth forms
		{"é", 1},  // combining acute adds nothing
		{"langchain", 9},
		{"…", 1}, // the truncation marker the tables append
	}
	for _, c := range cases {
		if got := DispWidth(c.s); got != c.want {
			t.Errorf("DispWidth(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

// TestRuneLenIsNotDispWidth guards the distinction the two helpers exist to
// draw — if they ever agree on wide input, one of them is wrong.
func TestRuneLenIsNotDispWidth(t *testing.T) {
	const s = "日本語"
	if RuneLen(s) != 3 {
		t.Errorf("RuneLen(%q) = %d, want 3", s, RuneLen(s))
	}
	if DispWidth(s) == RuneLen(s) {
		t.Error("DispWidth and RuneLen agree on wide input; the distinction is lost")
	}
	if RuneLen("abc") != DispWidth("abc") {
		t.Error("the two must agree on ASCII, where every golden lives")
	}
}
