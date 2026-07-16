package purl

import "testing"

func TestPurls(t *testing.T) {
	if got := Generic("llama.gguf", "ABCD"); got != "pkg:generic/llama.gguf?checksum=sha256:abcd" {
		t.Errorf("Generic = %q", got)
	}
	if got := Generic("x", ""); got != "" {
		t.Errorf("Generic without checksum = %q, want empty (a name identifies nothing)", got)
	}
	if got := HuggingFace("Meta-Llama", "Llama-3-8B", "abc123"); got != "pkg:huggingface/meta-llama/llama-3-8b@abc123" {
		t.Errorf("HuggingFace = %q", got)
	}
	if got, err := Package("pypi", "", "Lang_Chain.Community", "0.2.1"); err != nil || got != "pkg:pypi/lang-chain-community@0.2.1" {
		t.Errorf("pypi = %q, %v (PEP 503 normalization)", got, err)
	}
	if got, err := Package("npm", "@LangChain", "core", "1.0.0"); err != nil || got != "pkg:npm/@langchain/core@1.0.0" {
		t.Errorf("npm = %q, %v", got, err)
	}
	if got, err := Package("golang", "github.com/Acme", "tool", "v1.2.3"); err != nil || got != "pkg:golang/github.com/acme/tool@v1.2.3" {
		t.Errorf("golang = %q, %v", got, err)
	}
	if _, err := Package("apt", "", "x", "1"); err == nil {
		t.Error("unknown ecosystem accepted")
	}
	if NormalizePyPI("Foo__Bar..baz") != "foo-bar-baz" {
		t.Error("NormalizePyPI wrong")
	}
}
