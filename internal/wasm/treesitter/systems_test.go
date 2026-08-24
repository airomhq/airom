package treesitter

import (
	"testing"
)

func TestGoParser_Extraction(t *testing.T) {
	parser := NewGoParser()

	source := []byte(`
package main

import "github.com/sashabaranov/go-openai"

func main() {
    req := openai.ChatCompletionRequest{
        Model: "gpt-4o",
        Messages: []openai.ChatCompletionMessage{
            {Role: openai.ChatMessageRoleUser, Content: "Hello"},
        },
    }
}
`)

	node, calls, err := parser.Parse(source)
	if err != nil {
		t.Fatalf("go parse failed: %v", err)
	}

	if node == nil || len(calls) == 0 {
		t.Fatalf("expected call site in Go code")
	}

	if calls[0].Kwargs["model"] != "gpt-4o" {
		t.Errorf("expected model gpt-4o, got %s", calls[0].Kwargs["model"])
	}
}

func TestRustParser_Extraction(t *testing.T) {
	parser := NewRustParser()

	source := []byte(`
use async_openai::types::CreateChatCompletionRequestArgs;

let request = CreateChatCompletionRequestArgs::default()
    .model("claude-3-5-sonnet-20241022")
    .max_tokens(512u16)
    .build()?;
`)

	node, calls, err := parser.Parse(source)
	if err != nil {
		t.Fatalf("rust parse failed: %v", err)
	}

	if node == nil || len(calls) == 0 {
		t.Fatalf("expected call site in Rust code")
	}

	if calls[0].Kwargs["model"] != "claude-3-5-sonnet-20241022" {
		t.Errorf("expected claude-3-5, got %s", calls[0].Kwargs["model"])
	}
}

func TestJavaParser_Extraction(t *testing.T) {
	parser := NewJavaParser()

	source := []byte(`
package com.enterprise.ai;

import dev.langchain4j.model.openai.OpenAiChatModel;

public class AIService {
    public static void main(String[] args) {
        OpenAiChatModel model = OpenAiChatModel.builder()
            .apiKey("demo")
            .modelName("gpt-4o-mini")
            .build();
    }
}
`)

	node, calls, err := parser.Parse(source)
	if err != nil {
		t.Fatalf("java parse failed: %v", err)
	}

	if node == nil || len(calls) == 0 {
		t.Fatalf("expected call site in Java code")
	}

	if calls[0].Kwargs["model"] != "gpt-4o-mini" {
		t.Errorf("expected gpt-4o-mini, got %s", calls[0].Kwargs["model"])
	}
}
