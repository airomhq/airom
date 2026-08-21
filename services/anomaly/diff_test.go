package anomaly

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestComputeDiff(t *testing.T) {
	base := &airom.Inventory{
		Source: airom.SourceInfo{Git: &airom.GitInfo{Commit: "c1"}},
		Components: []airom.Component{
			{
				ID: "c1", PURL: "pkg:pypi/openai", Version: airom.KnownString("1.0.0"), Provider: airom.KnownString("OpenAI"),
				Model: &airom.ModelFacet{
					GenerationParams: []airom.BoundParam{
						{Name: "temperature", Value: "0.5"},
						{Name: "top_p", Value: "1.0"},
					},
				},
			},
			{ID: "c2", PURL: "pkg:npm/removed", Version: airom.KnownString("1.0.0")},
			{ID: "c4", PURL: "", Version: airom.KnownString("1.0.0")}, // test fallback to ID
		},
	}

	head := &airom.Inventory{
		Source: airom.SourceInfo{Git: &airom.GitInfo{Commit: "c2"}},
		Components: []airom.Component{
			{
				ID: "c1", PURL: "pkg:pypi/openai", Version: airom.KnownString("2.0.0"), Provider: airom.KnownString("OpenAICorp"),
				Model: &airom.ModelFacet{
					GenerationParams: []airom.BoundParam{
						{Name: "temperature", Value: "0.9"},
						{Name: "max_tokens", Value: "100"},
					},
				},
			},
			{ID: "c3", PURL: "pkg:npm/added", Version: airom.KnownString("1.0.0")},
			{ID: "c4", PURL: "", Version: airom.KnownString("1.1.0")},
		},
	}

	report := ComputeDiff(base, head)
	if report.BaseCommit != "c1" {
		t.Errorf("expected BaseCommit c1, got %v", report.BaseCommit)
	}
	if report.HeadCommit != "c2" {
		t.Errorf("expected HeadCommit c2, got %v", report.HeadCommit)
	}

	if len(report.Added) != 1 || report.Added[0].ID != "c3" {
		t.Errorf("expected 1 added component c3")
	}

	if len(report.Removed) != 1 || report.Removed[0].ID != "c2" {
		t.Errorf("expected 1 removed component c2")
	}

	if len(report.Modified) != 2 {
		t.Fatalf("expected 2 modified components, got %d", len(report.Modified))
	}

	var m1, m4 ComponentDelta
	for _, m := range report.Modified {
		if m.ComponentID == "c1" {
			m1 = m
		}
		if m.ComponentID == "c4" {
			m4 = m
		}
	}

	if m1.OldVersion != "1.0.0" || m1.NewVersion != "2.0.0" {
		t.Errorf("version mismatch m1")
	}
	if m4.OldVersion != "1.0.0" || m4.NewVersion != "1.1.0" {
		t.Errorf("version mismatch m4")
	}

	if p, ok := m1.ParamDeltas["temperature"]; !ok || p.OldValue != "0.5" || p.NewValue != "0.9" {
		t.Errorf("temperature param delta mismatch")
	}

	if p, ok := m1.ParamDeltas["max_tokens"]; !ok || p.OldValue != "" || p.NewValue != "100" {
		t.Errorf("max_tokens param delta mismatch")
	}

	if p, ok := m1.ParamDeltas["top_p"]; !ok || p.OldValue != "1.0" || p.NewValue != "" {
		t.Errorf("top_p param delta mismatch")
	}
}

func TestComputeDiffNil(t *testing.T) {
	report := ComputeDiff(nil, nil)
	if len(report.Added) != 0 || len(report.Removed) != 0 || len(report.Modified) != 0 {
		t.Errorf("expected empty diff")
	}
}
