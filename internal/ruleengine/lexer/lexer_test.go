package lexer

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/Roro1727/airom/internal/classify"
)

// allLangs is every language with a real lexer.
var allLangs = []classify.Language{
	classify.LangPython,
	classify.LangJavaScript,
	classify.LangTypeScript,
	classify.LangGo,
	classify.LangJava,
	classify.LangRust,
	classify.LangCSharp,
	classify.LangKotlin,
}

// checkTiling asserts regions tile [0, len(src)) exactly: sorted, non-empty,
// contiguous, full cover, valid types. Shared with FuzzClassify.
func checkTiling(t *testing.T, label string, src []byte, regions []Region) {
	t.Helper()
	if len(src) == 0 {
		if len(regions) != 0 {
			t.Fatalf("%s: empty input produced %d regions", label, len(regions))
		}
		return
	}
	if len(regions) == 0 {
		t.Fatalf("%s: no regions for %d bytes", label, len(src))
	}
	prev := 0
	for k, r := range regions {
		if r.Start != prev {
			t.Fatalf("%s: region %d starts at %d, want %d (gap/overlap)", label, k, r.Start, prev)
		}
		if r.End <= r.Start {
			t.Fatalf("%s: region %d is empty or inverted [%d,%d)", label, k, r.Start, r.End)
		}
		if r.Type > String {
			t.Fatalf("%s: region %d has invalid type %d", label, k, r.Type)
		}
		prev = r.End
	}
	if prev != len(src) {
		t.Fatalf("%s: regions end at %d, want %d", label, prev, len(src))
	}
}

// typeAt returns the type of the region containing offset, failing the test
// if no region does.
func typeAt(t *testing.T, regions []Region, off int) RegionType {
	t.Helper()
	for _, r := range regions {
		if off >= r.Start && off < r.End {
			return r.Type
		}
	}
	t.Fatalf("no region contains offset %d (regions: %v)", off, regions)
	return 0
}

// offsetOf locates sub's first occurrence in src, failing on fixture typos.
func offsetOf(t *testing.T, src, sub string) int {
	t.Helper()
	i := strings.Index(src, sub)
	if i < 0 {
		t.Fatalf("fixture bug: %q not found in %q", sub, src)
	}
	return i
}

// A check asserts the region type at (first occurrence of sub) + delta.
type check struct {
	sub   string
	delta int
	want  RegionType
}

func TestClassifyFixtures(t *testing.T) {
	fixtures := []struct {
		name   string
		lang   classify.Language
		src    string
		checks []check
	}{
		{
			name: "python/triple-quote-with-hash-and-quotes",
			lang: classify.LangPython,
			src:  `x = """a # not comment 'q' "w" b""" # real` + "\ny = 1",
			checks: []check{
				{"x =", 0, Code},
				{"# not comment", 0, String},
				{"'q'", 0, String},
				{`"w"`, 0, String},
				{"# real", 0, Comment},
				{"y = 1", 0, Code},
			},
		},
		{
			name: "python/raw-f-string",
			lang: classify.LangPython,
			src:  `p = rf"C:\path\{n}" # c`,
			checks: []check{
				{"p =", 0, Code},
				{`rf"`, 0, String}, // the prefix is part of the String region
				{`C:\path`, 0, String},
				{"{n}", 0, String}, // interpolation hole stays String
				{"# c", 0, Comment},
			},
		},
		{
			name: "python/escaped-quote-then-comment",
			lang: classify.LangPython,
			src:  `s = "a\"b" # real comment`,
			checks: []check{
				{"s =", 0, Code},
				{`a\"b`, 0, String},
				{"# real comment", 0, Comment},
			},
		},
		{
			name: "python/comment-ends-before-newline",
			lang: classify.LangPython,
			src:  "# c\nx = 1",
			checks: []check{
				{"# c", 0, Comment},
				{"\nx", 0, Code}, // the newline byte itself is Code
				{"x = 1", 0, Code},
			},
		},
		{
			name: "javascript/template-literal",
			lang: classify.LangJavaScript,
			src:  "const s = `a // not comment ' ${x+1} b`; // real",
			checks: []check{
				{"const", 0, Code},
				{"// not comment", 0, String},
				{"' ${", 0, String},
				{"${x+1}", 0, String}, // interpolation hole stays String
				{"; //", 0, Code},
				{"// real", 0, Comment},
			},
		},
		{
			name: "javascript/unterminated-block-comment",
			lang: classify.LangJavaScript,
			src:  "let a = 1; /* never closed\nmore text",
			checks: []check{
				{"let a", 0, Code},
				{"/* never", 0, Comment},
				{"more text", 0, Comment}, // extends to EOF
			},
		},
		{
			name: "javascript/escaped-quote-then-comment",
			lang: classify.LangJavaScript,
			src:  `x = "a\"b" // real comment`,
			checks: []check{
				{`a\"b`, 0, String},
				{"// real comment", 0, Comment},
			},
		},
		{
			name: "typescript/unterminated-string-ends-at-newline",
			lang: classify.LangTypeScript,
			src:  `const s = "abc` + "\nnext();",
			checks: []check{
				{`"abc`, 0, String},
				{"\nnext", 0, Code}, // the newline terminates the string as Code
				{"next()", 0, Code},
			},
		},
		{
			name: "go/raw-string-with-line-comment",
			lang: classify.LangGo,
			src:  "s := `a // not comment\nline2` // real",
			checks: []check{
				{"s :=", 0, Code},
				{"// not comment", 0, String},
				{"line2", 0, String}, // raw strings are multiline
				{"// real", 0, Comment},
			},
		},
		{
			name: "go/rune-and-block-comment",
			lang: classify.LangGo,
			src:  `r := '\'' /* block */ x := 2`,
			checks: []check{
				{`'\''`, 0, String},
				{"/* block */", 0, Comment},
				{"x := 2", 0, Code},
			},
		},
		{
			name: "java/text-block",
			lang: classify.LangJava,
			src:  `String s = """` + "\n" + `line // not comment "q"` + "\n" + `"""; // real`,
			checks: []check{
				{"String s", 0, Code},
				{"// not comment", 0, String},
				{`"q"`, 0, String},
				{"; //", 0, Code},
				{"// real", 0, Comment},
			},
		},
		{
			name: "java/char-literal",
			lang: classify.LangJava,
			src:  `char c = 'x'; // note`,
			checks: []check{
				{"'x'", 0, String},
				{"// note", 0, Comment},
			},
		},
		{
			name: "rust/nested-block-comment-two-deep",
			lang: classify.LangRust,
			src:  "/* a /* b */ c */ fn main() {}",
			checks: []check{
				{"a /*", 0, Comment},
				{" b ", 1, Comment},
				{" c ", 1, Comment}, // still inside after the inner close
				{"fn main", 0, Code},
			},
		},
		{
			name: "rust/raw-string-with-quotes",
			lang: classify.LangRust,
			src:  `let s = r#"a "quoted" b"#; // c`,
			checks: []check{
				{"let", 0, Code},
				{`r#"`, 0, String}, // the r# prefix is part of the String region
				{`"quoted"`, 0, String},
				{"; //", 0, Code},
				{"// c", 0, Comment},
			},
		},
		{
			name: "rust/lifetime-is-not-a-string",
			lang: classify.LangRust,
			src:  "fn f<'a>(x: &'a str) -> &'a str { x } // done",
			checks: []check{
				{"<'a>", 1, Code}, // the ' tick itself
				{"&'a str", 1, Code},
				{"str {", 0, Code},
				{"// done", 0, Comment},
			},
		},
		{
			name: "rust/char-escape-and-byte-string",
			lang: classify.LangRust,
			src:  `let c = '\n'; let b = b"by\"tes"; let t = 'x';`,
			checks: []check{
				{"let c", 0, Code},
				{`'\n'`, 0, String},
				{`b"by`, 0, String}, // the b prefix is part of the String region
				{`\"tes`, 0, String},
				{"'x'", 0, String},
			},
		},
		{
			name: "csharp/verbatim-doubled-quote-stays-inside",
			lang: classify.LangCSharp,
			src:  `var s = @"a""b"; // c`,
			checks: []check{
				{"var", 0, Code},
				{`@"`, 0, String}, // the @ prefix is part of the String region
				{`""b`, 0, String},
				{`""b`, 2, String}, // the b after the escaped quote
				{"; //", 0, Code},
				{"// c", 0, Comment},
			},
		},
		{
			name: "csharp/raw-string",
			lang: classify.LangCSharp,
			src:  `var s = """a "b" c"""; // d`,
			checks: []check{
				{`"b"`, 0, String},
				{"; //", 0, Code},
				{"// d", 0, Comment},
			},
		},
		{
			name: "csharp/interpolated-and-verbatim-interpolated",
			lang: classify.LangCSharp,
			src:  `var s = $"{x}"; var t = @$"a""b{z}"; // c`,
			checks: []check{
				{"{x}", 0, String},
				{"var t", 0, Code},
				{`""b{z}`, 0, String},
				{"// c", 0, Comment},
			},
		},
		{
			name: "csharp/char-literal",
			lang: classify.LangCSharp,
			src:  `char c = 'x'; /* b */ int y;`,
			checks: []check{
				{"'x'", 0, String},
				{"/* b */", 0, Comment},
				{"int y", 0, Code},
			},
		},
		{
			name: "kotlin/nested-block-comment",
			lang: classify.LangKotlin,
			src:  "/* o /* i */ still */ val x = 1",
			checks: []check{
				{"i */", 0, Comment},
				{"still", 0, Comment},
				{"val x", 0, Code},
			},
		},
		{
			name: "kotlin/unterminated-nested-comment",
			lang: classify.LangKotlin,
			src:  "/* a /* b */ still open",
			checks: []check{
				{"/* a", 0, Comment},
				{"still open", 0, Comment}, // depth never reaches 0: EOF
			},
		},
		{
			name: "kotlin/raw-triple-quoted",
			lang: classify.LangKotlin,
			src:  `val s = """a "q" // not ${x}""" // real`,
			checks: []check{
				{"val s", 0, Code},
				{`"q"`, 0, String},
				{"// not", 0, String},
				{"${x}", 0, String}, // interpolation hole stays String
				{"// real", 0, Comment},
			},
		},
		{
			name: "kotlin/interpolation-in-plain-string",
			lang: classify.LangKotlin,
			src:  `val s = "a ${b.c} d" // real`,
			checks: []check{
				{"val s", 0, Code},
				{"${b.c}", 0, String},
				{"// real", 0, Comment},
			},
		},
	}
	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(tc.src)
			regions := Classify(tc.lang, src)
			checkTiling(t, tc.name, src, regions)
			for _, c := range tc.checks {
				off := offsetOf(t, tc.src, c.sub) + c.delta
				if got := typeAt(t, regions, off); got != c.want {
					t.Errorf("offset %d (%q+%d): got %v, want %v\nregions: %v",
						off, c.sub, c.delta, got, c.want, regions)
				}
			}
		})
	}
}

func TestEmptyInput(t *testing.T) {
	langs := append(slices.Clone(allLangs), classify.LangUnknown, classify.LangYAML)
	for _, lang := range langs {
		if got := Classify(lang, nil); len(got) != 0 {
			t.Errorf("Classify(%q, nil) = %v, want no regions", lang, got)
		}
		if got := Classify(lang, []byte{}); len(got) != 0 {
			t.Errorf("Classify(%q, empty) = %v, want no regions", lang, got)
		}
	}
	if got := Mask(nil, nil, func(RegionType) bool { return false }); len(got) != 0 {
		t.Errorf("Mask(nil, ...) has length %d, want 0", len(got))
	}
}

func TestUnknownLanguageAllCode(t *testing.T) {
	src := []byte("# not a comment here\n\"not a string\" // nope")
	unsupported := []classify.Language{
		classify.LangUnknown, classify.LangYAML, classify.LangJSON, classify.LangTOML,
	}
	want := []Region{{Start: 0, End: len(src), Type: Code}}
	for _, lang := range unsupported {
		if got := Classify(lang, src); !slices.Equal(got, want) {
			t.Errorf("Classify(%q) = %v, want %v", lang, got, want)
		}
	}
}

func TestSupported(t *testing.T) {
	for _, lang := range allLangs {
		if !Supported(lang) {
			t.Errorf("Supported(%q) = false, want true", lang)
		}
	}
	unsupported := []classify.Language{
		classify.LangUnknown, classify.LangYAML, classify.LangJSON,
		classify.LangTOML, classify.Language("cobol"),
	}
	for _, lang := range unsupported {
		if Supported(lang) {
			t.Errorf("Supported(%q) = true, want false", lang)
		}
	}
}

func TestSingleGiantComment(t *testing.T) {
	cases := []struct {
		lang classify.Language
		src  string
	}{
		{classify.LangPython, `# one giant comment with 'quotes' and "quotes", no newline`},
		{classify.LangGo, "/* one giant unterminated block comment\nspanning lines"},
		{classify.LangRust, "/* /* /* deeply nested and never closed"},
	}
	for _, tc := range cases {
		src := []byte(tc.src)
		regions := Classify(tc.lang, src)
		checkTiling(t, string(tc.lang), src, regions)
		want := []Region{{Start: 0, End: len(src), Type: Comment}}
		if !slices.Equal(regions, want) {
			t.Errorf("Classify(%q, giant comment) = %v, want %v", tc.lang, regions, want)
		}
	}
}

func TestMask(t *testing.T) {
	keepNonComment := func(rt RegionType) bool { return rt != Comment }
	src := []byte("a := 1 /* c1\nc2 \"s\"\nc3 */ b := \"x\" // tail\r\nc := 3")
	snapshot := slices.Clone(src)

	regions := Classify(classify.LangGo, src)
	checkTiling(t, "mask-fixture", src, regions)
	masked := Mask(src, regions, keepNonComment)

	if len(masked) != len(src) {
		t.Fatalf("Mask changed length: %d != %d", len(masked), len(src))
	}
	if !bytes.Equal(src, snapshot) {
		t.Fatal("Mask modified its input buffer")
	}
	if got, want := bytes.Count(masked, []byte{'\n'}), bytes.Count(src, []byte{'\n'}); got != want {
		t.Fatalf("Mask changed line count: %d != %d", got, want)
	}
	for i, b := range src {
		if (b == '\n' || b == '\r') && masked[i] != b {
			t.Fatalf("Mask overwrote newline byte at offset %d", i)
		}
	}
	for _, r := range regions {
		if keepNonComment(r.Type) {
			if !bytes.Equal(masked[r.Start:r.End], src[r.Start:r.End]) {
				t.Errorf("kept %v region [%d,%d) not byte-identical: %q != %q",
					r.Type, r.Start, r.End, masked[r.Start:r.End], src[r.Start:r.End])
			}
			continue
		}
		for j := r.Start; j < r.End; j++ {
			if b := masked[j]; b != ' ' && b != '\n' && b != '\r' {
				t.Errorf("masked %v region byte at %d is %q, want space or newline",
					r.Type, j, b)
			}
		}
	}

	// Keeping only String must blank comment AND code bytes.
	stringOnly := Mask(src, regions, func(rt RegionType) bool { return rt == String })
	for _, r := range regions {
		if r.Type == String {
			if !bytes.Equal(stringOnly[r.Start:r.End], src[r.Start:r.End]) {
				t.Errorf("string region [%d,%d) not preserved", r.Start, r.End)
			}
			continue
		}
		for j := r.Start; j < r.End; j++ {
			if b := stringOnly[j]; b != ' ' && b != '\n' && b != '\r' {
				t.Errorf("non-string byte at %d survived masking: %q", j, b)
			}
		}
	}
}

func TestMaskDefensive(t *testing.T) {
	src := []byte("abc\ndef")

	// nil keep rejects nothing: an unmodified copy.
	if got := Mask(src, []Region{{Start: 0, End: 7, Type: Comment}}, nil); !bytes.Equal(got, src) {
		t.Errorf("Mask with nil keep = %q, want %q", got, src)
	}

	// Out-of-range regions are clamped, never panic.
	bogus := []Region{{Start: -5, End: 999, Type: Comment}}
	got := Mask(src, bogus, func(rt RegionType) bool { return rt != Comment })
	if len(got) != len(src) {
		t.Fatalf("Mask with bogus regions changed length: %d != %d", len(got), len(src))
	}
	if want := []byte("   \n   "); !bytes.Equal(got, want) {
		t.Errorf("Mask with bogus regions = %q, want %q", got, want)
	}
}
