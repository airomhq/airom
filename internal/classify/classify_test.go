package classify

import (
	"bytes"
	"testing"
)

func TestLanguageOf(t *testing.T) {
	cases := map[string]Language{
		"app/chat.py":       LangPython,
		"x.PY":              LangPython,
		"web/index.ts":      LangTypeScript,
		"web/App.tsx":       LangTypeScript,
		"lib.mjs":           LangJavaScript,
		"main.go":           LangGo,
		"Svc.java":          LangJava,
		"lib.rs":            LangRust,
		"Program.cs":        LangCSharp,
		"App.kt":            LangKotlin,
		"build.gradle.kts":  LangKotlin,
		"conf/values.yaml":  LangYAML,
		"config.json":       LangJSON,
		"pyproject.toml":    LangTOML,
		"model.safetensors": LangUnknown,
		"README.md":         LangUnknown,
	}
	for path, want := range cases {
		if got := LanguageOf(path); got != want {
			t.Errorf("LanguageOf(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestMatchMagic(t *testing.T) {
	pad := func(b []byte) []byte { return append(b, bytes.Repeat([]byte{'x'}, 64)...) }
	cases := []struct {
		name   string
		header []byte
		want   string
	}{
		{"gguf", pad([]byte("GGUF")), "gguf"},
		{"hdf5", pad([]byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'}), "hdf5"},
		{"tflite", pad([]byte{1, 2, 3, 4, 'T', 'F', 'L', '3'}), "tflite"},
		{"zip", pad([]byte{'P', 'K', 0x03, 0x04}), "zip"},
		{"pickle", pad([]byte{0x80, 0x04}), "pickle"},
		{"onnx-ish", pad([]byte{0x08, 0x07}), "onnx-protobuf"},
		{"text", []byte("import openai\n"), ""},
		{"empty", nil, ""},
		{"short gguf prefix only", []byte("GG"), ""},
	}
	for _, tc := range cases {
		if got := MatchMagic(tc.header); got != tc.want {
			t.Errorf("%s: MatchMagic = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestMagicOrderSpecificBeforeWeak(t *testing.T) {
	// HDF5 starts with 0x89 — must not be eaten by a weak single-byte rule;
	// and a GGUF file must never classify as onnx/pickle.
	gguf := append([]byte("GGUF"), 0x08, 0x80)
	if got := MatchMagic(gguf); got != "gguf" {
		t.Errorf("gguf header matched %q", got)
	}
}

func TestIsBinary(t *testing.T) {
	if IsBinary([]byte("plain text\nwith lines\n")) {
		t.Error("text classified binary")
	}
	if !IsBinary([]byte{'a', 0x00, 'b'}) {
		t.Error("NUL not classified binary")
	}
	// NUL beyond the 8KB sniff window is ignored (matches git).
	big := append(bytes.Repeat([]byte{'a'}, 9*1024), 0x00)
	if IsBinary(big) {
		t.Error("NUL past sniff window classified binary")
	}
}
