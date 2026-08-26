package cli

import (
	"bytes"
	"testing"
)

func TestCLI_HubCommands(t *testing.T) {
	// HF Hub
	rootHF := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var outHF bytes.Buffer
	rootHF.SetOut(&outHF)
	rootHF.SetArgs([]string{"hub", "hf", "meta-llama/Meta-Llama-3.1-8B-Instruct"})
	if err := rootHF.Execute(); err != nil {
		t.Fatalf("hub hf command failed: %v", err)
	}
	if !bytes.Contains(outHF.Bytes(), []byte("Meta-Llama-3.1-8B-Instruct")) {
		t.Errorf("expected model name in HF output, got:\n%s", outHF.String())
	}

	// Ollama Hub
	rootOllama := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var outOllama bytes.Buffer
	rootOllama.SetOut(&outOllama)
	rootOllama.SetArgs([]string{"hub", "ollama"})
	if err := rootOllama.Execute(); err != nil {
		t.Fatalf("hub ollama command failed: %v", err)
	}
	if !bytes.Contains(outOllama.Bytes(), []byte("llama3.1:8b")) {
		t.Errorf("expected llama3.1 in Ollama output, got:\n%s", outOllama.String())
	}

	// Serverless Hub
	rootSL := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var outSL bytes.Buffer
	rootSL.SetOut(&outSL)
	rootSL.SetArgs([]string{"hub", "serverless"})
	if err := rootSL.Execute(); err != nil {
		t.Fatalf("hub serverless command failed: %v", err)
	}
	if !bytes.Contains(outSL.Bytes(), []byte("llama-3.3-70b-versatile")) {
		t.Errorf("expected groq model in serverless output, got:\n%s", outSL.String())
	}
}
