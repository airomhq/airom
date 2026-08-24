package treesitter

import (
	"testing"
)

func TestQA_AdversarialSystemsBrokenSyntax(t *testing.T) {
	goP := NewGoParser()
	rustP := NewRustParser()
	javaP := NewJavaParser()

	brokenCode := []byte(`
struct Broken<T, U<V>> {
    Model: "gpt-4o",
    unclosed: {{{
`)

	_, callsGo, errGo := goP.Parse(brokenCode)
	if errGo != nil {
		t.Fatalf("go parser errored on syntax: %v", errGo)
	}
	if len(callsGo) == 0 {
		t.Errorf("go parser missed model in broken struct")
	}

	_, _, errRust := rustP.Parse(brokenCode)
	if errRust != nil {
		t.Fatalf("rust parser errored: %v", errRust)
	}

	_, _, errJava := javaP.Parse(brokenCode)
	if errJava != nil {
		t.Fatalf("java parser errored: %v", errJava)
	}
}

func TestQA_AdversarialUnicodeIdentifiers(t *testing.T) {
	goP := NewGoParser()

	unicodeCode := []byte(`
type Модель struct {
    Model: "gpt-4o"
}
`)

	_, calls, err := goP.Parse(unicodeCode)
	if err != nil {
		t.Fatalf("unicode parser error: %v", err)
	}

	if len(calls) == 0 || calls[0].Kwargs["model"] != "gpt-4o" {
		t.Fatalf("failed to extract model with unicode struct name")
	}
}
