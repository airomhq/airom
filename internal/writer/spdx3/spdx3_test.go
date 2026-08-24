package spdx3

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

func TestSPDX3_BasicSerialization(t *testing.T) {
	w := New(writer.Options{})
	if w.Format() != "spdx3" {
		t.Fatalf("expected format spdx3, got %s", w.Format())
	}

	inv := &airom.Inventory{
		SchemaVersion: "1",
		Timestamp:     time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC),
		Tool: airom.ToolInfo{
			Name:    "airom",
			Version: "1.0.0",
		},
		Source: airom.SourceInfo{
			Kind:   "dir",
			Target: "enterprise-agent-stack",
		},
		Components: []airom.Component{
			{
				ID:       "airom:c1",
				Kind:     airom.KindHostedLLM,
				Name:     "gpt-4o",
				Provider: airom.KnownString("openai"),
				Version:  airom.KnownString("2024-08-06"),
			},
			{
				ID:       "airom:c2",
				Kind:     airom.KindFramework,
				Name:     "langchain",
				Provider: airom.KnownString("langchain-ai"),
				Version:  airom.KnownString("0.2.0"),
				PURL:     "pkg:pypi/langchain@0.2.0",
				Licenses: []airom.License{{SPDXID: "MIT"}},
				Hashes: []airom.Hash{
					{Alg: "SHA-256", Hex: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
				},
			},
		},
		Relationships: []airom.Relationship{
			{
				From: "airom:c2",
				To:   "airom:c1",
				Type: airom.RelDependsOn,
			},
		},
	}

	var buf bytes.Buffer
	if err := w.Write(&buf, inv); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Validate JSON-LD decoding
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("failed to unmarshal JSON-LD output: %v", err)
	}

	if raw["@context"] != ContextIRI {
		t.Fatalf("expected @context %s, got %v", ContextIRI, raw["@context"])
	}

	graph, ok := raw["@graph"].([]any)
	if !ok || len(graph) == 0 {
		t.Fatalf("expected non-empty @graph, got %v", raw["@graph"])
	}

	// We expect: 1 SoftwareAgent + 1 SpdxDocument + 2 Packages + 1 DocContains Rel + 1 DependsOn Rel = 6 elements
	if len(graph) != 6 {
		t.Errorf("expected 6 graph elements, got %d", len(graph))
	}
}

func TestSPDX3_DeterministicOrdering(t *testing.T) {
	w := New(writer.Options{})
	inv := &airom.Inventory{
		Timestamp: time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC),
		Tool:      airom.ToolInfo{Name: "airom", Version: "1.0.0"},
		Source:    airom.SourceInfo{Kind: "dir", Target: "deterministic-test"},
		Components: []airom.Component{
			{ID: "airom:z_comp", Kind: airom.KindFramework, Name: "zebra", Provider: airom.KnownString("p1")},
			{ID: "airom:a_comp", Kind: airom.KindFramework, Name: "alpha", Provider: airom.KnownString("p2")},
			{ID: "airom:m_comp", Kind: airom.KindHostedLLM, Name: "middle", Provider: airom.KnownString("p3")},
		},
	}

	var buf1, buf2 bytes.Buffer
	if err := w.Write(&buf1, inv); err != nil {
		t.Fatalf("run 1 failed: %v", err)
	}
	if err := w.Write(&buf2, inv); err != nil {
		t.Fatalf("run 2 failed: %v", err)
	}

	if buf1.String() != buf2.String() {
		t.Fatalf("serialization is not byte-for-byte deterministic across runs")
	}
}

func TestSPDX3_EmptyInventory(t *testing.T) {
	w := New(writer.Options{})
	inv := &airom.Inventory{
		Timestamp: time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC),
		Tool:      airom.ToolInfo{Name: "airom", Version: "1.0.0"},
		Source:    airom.SourceInfo{Kind: "dir", Target: "empty-test"},
	}

	var buf bytes.Buffer
	if err := w.Write(&buf, inv); err != nil {
		t.Fatalf("failed to write empty inventory: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	graph := raw["@graph"].([]any)
	if len(graph) < 2 {
		t.Fatalf("expected at least 2 graph elements for empty inventory, got %d", len(graph))
	}
}
