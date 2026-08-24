package treesitter

import (
	"testing"
)

func TestPythonParser_Extraction(t *testing.T) {
	parser := NewPythonParser()

	source := []byte(`
import openai
from transformers import AutoModelForCausalLM, pipeline

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    temperature=0.2,
    max_tokens=1024
)

model = AutoModelForCausalLM.from_pretrained("meta-llama/Meta-Llama-3-8B-Instruct")
pipe = pipeline("text-generation", model="mistralai/Mistral-7B-v0.1")
`)

	node, calls, err := parser.Parse(source)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if node == nil {
		t.Fatalf("expected non-nil root AST node")
	}

	if len(calls) < 3 {
		t.Fatalf("expected at least 3 call sites, got %d", len(calls))
	}

	foundGPT := false
	foundLlama := false
	foundMistral := false

	for _, c := range calls {
		if c.Kwargs["model"] == "gpt-4o" && c.Kwargs["temperature"] == "0.2" {
			foundGPT = true
		}
		if c.Kwargs["model"] == "meta-llama/Meta-Llama-3-8B-Instruct" {
			foundLlama = true
		}
		if c.Kwargs["model"] == "mistralai/Mistral-7B-v0.1" {
			foundMistral = true
		}
	}

	if !foundGPT {
		t.Errorf("gpt-4o call site with temperature=0.2 not found")
	}
	if !foundLlama {
		t.Errorf("llama from_pretrained not found")
	}
	if !foundMistral {
		t.Errorf("mistral pipeline not found")
	}
}

func TestTypeScriptParser_Extraction(t *testing.T) {
	parser := NewTypeScriptParser()

	source := []byte(`
import { openai } from '@ai-sdk/openai';
import { generateText } from 'ai';

const model = openai('gpt-4o');

const response = await client.chat.completions.create({
    model: "claude-3-5-sonnet-20241022",
    temperature: 0.5
});
`)

	node, calls, err := parser.Parse(source)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if node == nil {
		t.Fatalf("expected non-nil root node")
	}

	if len(calls) < 2 {
		t.Fatalf("expected at least 2 call sites, got %d", len(calls))
	}

	foundVercel := false
	foundClaude := false

	for _, c := range calls {
		if c.Kwargs["model"] == "gpt-4o" {
			foundVercel = true
		}
		if c.Kwargs["model"] == "claude-3-5-sonnet-20241022" && c.Kwargs["temperature"] == "0.5" {
			foundClaude = true
		}
	}

	if !foundVercel {
		t.Errorf("vercel openai('gpt-4o') not found")
	}
	if !foundClaude {
		t.Errorf("claude call site not found")
	}
}
