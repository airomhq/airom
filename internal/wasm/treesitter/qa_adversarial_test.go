package treesitter

import (
	"strings"
	"testing"
)

func TestQA_AdversarialMinifiedAndLongLines(t *testing.T) {
	tsParser := NewTypeScriptParser()

	// Construct a 200KB single-line minified file
	var b strings.Builder
	b.WriteString("var a=1;var b=2;")
	for i := 0; i < 5000; i++ {
		b.WriteString("function f(){return 42;};")
	}
	b.WriteString(`client.create({model:"gpt-4o",temperature:0.1});`)

	minified := []byte(b.String())

	node, calls, err := tsParser.Parse(minified)
	if err != nil {
		t.Fatalf("failed on minified input: %v", err)
	}

	if node == nil {
		t.Fatalf("expected root node")
	}

	if len(calls) == 0 {
		t.Fatalf("failed to locate call site inside minified line")
	}

	if calls[0].Kwargs["model"] != "gpt-4o" {
		t.Errorf("expected model gpt-4o, got %s", calls[0].Kwargs["model"])
	}
}

func TestQA_AdversarialBrokenStringsAndEscapes(t *testing.T) {
	pyParser := NewPythonParser()

	brokenCode := []byte(`
s = "unterminated string literal
x = 'escaped \' quote'
client.create(model="gpt-4o", temperature="invalid_string_float")
`)

	_, calls, err := pyParser.Parse(brokenCode)
	if err != nil {
		t.Fatalf("broken syntax caused panic/error: %v", err)
	}

	if len(calls) == 0 {
		t.Fatalf("failed to extract valid call following syntax anomalies")
	}
}

func TestQA_AdversarialEmptyAndWhitespaceOnly(t *testing.T) {
	pyParser := NewPythonParser()
	tsParser := NewTypeScriptParser()

	emptyInputs := [][]byte{
		{},
		[]byte(""),
		[]byte("   \n\n\t  \n  "),
		[]byte("# Only comment 1\n# Only comment 2"),
		[]byte("// JS comment 1\n/* Multi-line\ncomment */"),
	}

	for i, in := range emptyInputs {
		_, callsPy, errPy := pyParser.Parse(in)
		if errPy != nil || len(callsPy) != 0 {
			t.Errorf("py case %d failed: err=%v, len(calls)=%d", i, errPy, len(callsPy))
		}

		_, callsTS, errTS := tsParser.Parse(in)
		if errTS != nil || len(callsTS) != 0 {
			t.Errorf("ts case %d failed: err=%v, len(calls)=%d", i, errTS, len(callsTS))
		}
	}
}
