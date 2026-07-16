package lexer

import (
	"slices"
	"testing"

	"github.com/Roro1727/airom/internal/classify"
)

// FuzzClassify asserts the structural contract on arbitrary bytes for all
// eight languages (plus the all-Code fallback): no panics, the regions tile
// [0, len(src)) exactly (sorted, contiguous, full cover), classification is
// deterministic, and Mask is length- and newline-preserving.
func FuzzClassify(f *testing.F) {
	seeds := []string{
		"",
		`x = """a # b ''' " """ # c`,
		"p = rf\"C:\\path\\{n}\" # c\n'''unterminated",
		"const s = `a // ${x} ' b`; // c\n\"open",
		"s := `raw // ok\n` + \"esc\\\"\" // c 'r'",
		`/* a /* b */ c */ r##"q " "# x"## b"z\"" 'x' '\u{7fff}' <'a, 'b>`,
		`var s = @"a""b" + $"{x}" + """raw " q"""; // c '\''`,
		`val k = """t ${x} " """ /* o /* i */ */ // c`,
		"\"a\\\"b\" // real comment",
		"\x80\xff\x00'\"`#//*/\\",
		"@$\"",
		"$$\"\"\"",
		"r#",
		"br########\"never closed",
		"'''",
		`"""`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	langs := append(slices.Clone(allLangs), classify.LangUnknown)
	f.Fuzz(func(t *testing.T, src []byte) {
		for _, lang := range langs {
			label := string(lang)
			if label == "" {
				label = "unknown"
			}
			regions := Classify(lang, src)
			checkTiling(t, label, src, regions)
			if again := Classify(lang, src); !slices.Equal(regions, again) {
				t.Fatalf("%s: Classify is not deterministic", label)
			}
			masked := Mask(src, regions, func(rt RegionType) bool { return rt != Comment })
			if len(masked) != len(src) {
				t.Fatalf("%s: Mask changed length: %d != %d", label, len(masked), len(src))
			}
			for i, b := range src {
				if (b == '\n' || b == '\r') && masked[i] != b {
					t.Fatalf("%s: Mask overwrote newline byte at offset %d", label, i)
				}
			}
		}
	})
}
