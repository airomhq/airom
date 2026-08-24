package spdx3

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer"
	_ "github.com/airomhq/airom/internal/writer/cdx"
	_ "github.com/airomhq/airom/internal/writer/nativejson"
	_ "github.com/airomhq/airom/internal/writer/sarifw"
	_ "github.com/airomhq/airom/internal/writer/tablew"
	_ "github.com/airomhq/airom/internal/writer/yamlw"
	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_MasterCrossFormatConformance(t *testing.T) {
	formats := []string{"json", "cyclonedx", "sarif", "yaml", "table", "spdx3"}

	inv := &airom.Inventory{
		SchemaVersion: "1",
		Timestamp:     time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
		Tool: airom.ToolInfo{
			Name:    "airom",
			Version: "1.0.0",
		},
		Source: airom.SourceInfo{
			Kind:   "dir",
			Target: "master-conformance-stack",
		},
		Components: []airom.Component{
			{
				ID:       "airom:claude35",
				Kind:     airom.KindHostedLLM,
				Name:     "claude-3-5-sonnet-20241022",
				Provider: airom.KnownString("anthropic"),
				Version:  airom.KnownString("20241022"),
				Model: &airom.ModelFacet{
					Architecture:  airom.KnownString("claude3"),
					ContextLength: airom.KnownInt64(200000),
					GenerationParams: []airom.BoundParam{
						{Name: "temperature", Value: "0.5"},
					},
				},
			},
			{
				ID:       "airom:qdrant",
				Kind:     airom.KindVectorDB,
				Name:     "qdrant",
				Provider: airom.KnownString("qdrant"),
				Version:  airom.KnownString("1.9.0"),
				PURL:     "pkg:docker/qdrant/qdrant@v1.9.0",
			},
			{
				ID:       "airom:hotpotqa",
				Kind:     airom.KindDataset,
				Name:     "hotpot_qa",
				Provider: airom.KnownString("hotpotqa"),
				Data: &airom.DataFacet{
					Format:    airom.KnownString("parquet"),
					SizeBytes: airom.KnownInt64(250000000),
				},
			},
		},
		Relationships: []airom.Relationship{
			{
				From: "airom:claude35",
				To:   "airom:qdrant",
				Type: airom.RelUses,
			},
			{
				From: "airom:claude35",
				To:   "airom:hotpotqa",
				Type: airom.RelTrainedOn,
			},
		},
	}

	opts := writer.Options{CDXVersion: "1.6", TableWide: true}

	for _, fmtName := range formats {
		t.Run(fmtName, func(t *testing.T) {
			w, err := writer.New(fmtName, opts)
			if err != nil {
				t.Fatalf("failed to create writer for %s: %v", fmtName, err)
			}

			var buf bytes.Buffer
			if err := w.Write(&buf, inv); err != nil {
				t.Fatalf("failed to write format %s: %v", fmtName, err)
			}

			if buf.Len() == 0 {
				t.Fatalf("format %s produced empty output", fmtName)
			}

			if fmtName == "spdx3" {
				var raw map[string]any
				if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
					t.Fatalf("failed to parse spdx3 JSON-LD: %v", err)
				}
				graph := raw["@graph"].([]any)
				// Expect: 1 Agent + 1 SpdxDocument + 3 Components + 1 DocContains + 2 User Rels = 8 elements
				if len(graph) != 8 {
					t.Errorf("expected 8 graph elements, got %d", len(graph))
				}
			}
		})
	}
}
