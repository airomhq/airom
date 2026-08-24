package spdx3

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_AdversarialCharacterInjection(t *testing.T) {
	w := New(writer.Options{})

	maliciousInputs := []string{
		`"><script>alert(1)</script>`,
		"model\x00with\x1fcontrol\x08chars",
		"DROP TABLE elements; --",
		"мodel-with-cyrillic-homoglyphs",
		"{\"@id\": \"injected-graph-node\"}",
		"https://evil.com/spdxdocs/payload",
	}

	for i, input := range maliciousInputs {
		inv := &airom.Inventory{
			Timestamp: time.Now().UTC(),
			Tool:      airom.ToolInfo{Name: "airom", Version: "1.0.0"},
			Source:    airom.SourceInfo{Kind: "dir", Target: input},
			Components: []airom.Component{
				{
					ID:       airom.ID(strings.ReplaceAll(input, " ", "_")),
					Kind:     airom.KindHostedLLM,
					Name:     input,
					Provider: airom.KnownString(input),
				},
			},
		}

		var buf bytes.Buffer
		if err := w.Write(&buf, inv); err != nil {
			t.Fatalf("case %d failed on input %q: %v", i, input, err)
		}

		// Ensure valid JSON-LD parsing
		var raw map[string]any
		if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
			t.Fatalf("case %d produced malformed JSON on input %q: %v", i, input, err)
		}
	}
}

func TestQA_AdversarialCircularRelationshipGraph(t *testing.T) {
	w := New(writer.Options{})

	inv := &airom.Inventory{
		Timestamp: time.Now().UTC(),
		Tool:      airom.ToolInfo{Name: "airom", Version: "1.0.0"},
		Source:    airom.SourceInfo{Kind: "dir", Target: "circular-graph"},
		Components: []airom.Component{
			{ID: "airom:node_a", Kind: airom.KindHostedLLM, Name: "node-a"},
			{ID: "airom:node_b", Kind: airom.KindHostedLLM, Name: "node-b"},
			{ID: "airom:node_c", Kind: airom.KindHostedLLM, Name: "node-c"},
		},
		Relationships: []airom.Relationship{
			{From: "airom:node_a", To: "airom:node_b", Type: airom.RelDependsOn},
			{From: "airom:node_b", To: "airom:node_c", Type: airom.RelDependsOn},
			{From: "airom:node_c", To: "airom:node_a", Type: airom.RelDependsOn},       // Cycle
			{From: "airom:node_a", To: "airom:node_a", Type: airom.RelDependsOn},       // Self-loop
			{From: "airom:node_a", To: "airom:non_existent", Type: airom.RelDependsOn}, // Orphan
		},
	}

	var buf bytes.Buffer
	if err := w.Write(&buf, inv); err != nil {
		t.Fatalf("failed to process circular graph: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	graph := raw["@graph"].([]any)
	if len(graph) == 0 {
		t.Fatalf("graph is empty")
	}
}

func TestQA_AdversarialMissingRequiredMetadata(t *testing.T) {
	w := New(writer.Options{})

	inv := &airom.Inventory{
		Timestamp: time.Time{},        // Zero timestamp
		Source:    airom.SourceInfo{}, // Empty source
		Components: []airom.Component{
			{
				ID:       "airom:sparse",
				Kind:     airom.KindHostedLLM,
				Name:     "",
				Provider: airom.UnknownString(),
				Version:  airom.UnknownString(),
			},
		},
	}

	var buf bytes.Buffer
	if err := w.Write(&buf, inv); err != nil {
		t.Fatalf("sparse inventory failed: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	graph := raw["@graph"].([]any)
	foundPkg := false
	for _, item := range graph {
		m := item.(map[string]any)
		if m["@type"] == "Package" {
			foundPkg = true
			if m["packageVersion"] != NoAssertion {
				t.Errorf("expected NOASSERTION packageVersion, got %v", m["packageVersion"])
			}
			if m["suppliedBy"] != NoAssertion {
				t.Errorf("expected NOASSERTION suppliedBy, got %v", m["suppliedBy"])
			}
		}
	}

	if !foundPkg {
		t.Fatalf("sparse package element missing in output graph")
	}
}
