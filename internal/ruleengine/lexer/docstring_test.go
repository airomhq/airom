package lexer_test

import (
	"testing"

	"github.com/airomhq/airom/internal/classify"
	"github.com/airomhq/airom/internal/ruleengine/lexer"
)

func TestPythonDocstringVsString(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want lexer.RegionType
	}{
		{"module docstring", `"""Doc."""` + "\nx = 1\n", lexer.Docstring},
		{"indented function docstring", "def f():\n    \"\"\"Doc.\"\"\"\n", lexer.Docstring},
		{"single-quote docstring", "def f():\n    '''Doc.'''\n", lexer.Docstring},
		{"assigned prompt", `P = """You are helpful."""` + "\n", lexer.String},
		{"dict value", `{"k": """v"""}` + "\n", lexer.String},
		{"call argument", `f("""text""")` + "\n", lexer.String},
		{"returned", "def f():\n    return \"\"\"x\"\"\"\n", lexer.String},
		{"concatenated", `a = "x" + """y"""` + "\n", lexer.String},
	}
	for _, tc := range cases {
		var got lexer.RegionType = 255
		for _, r := range lexer.Classify(classify.LangPython, []byte(tc.src)) {
			if r.Type == lexer.Docstring || r.Type == lexer.String {
				got = r.Type
				break
			}
		}
		if got != tc.want {
			t.Errorf("%s: classified as %v, want %v", tc.name, got, tc.want)
		}
	}
}
