package anomaly

import (
	"testing"

	"github.com/airomhq/airom/internal/approved"
	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_E2E(t *testing.T) {
	manifest := &approved.ApprovedManifest{
		Approved: []approved.ComponentApproval{
			{
				PURL: "pkg:npm/config",
				PermittedConfig: map[string]string{
					"max_temp": "0.5",
				},
			},
			{
				PURL: "pkg:npm/model",
			},
		},
	}

	t.Run("Clean diff", func(t *testing.T) {
		report := EvaluateAnomalies(DiffReport{}, manifest)
		if !report.Clean || len(report.Anomalies) != 0 {
			t.Errorf("Expected Clean: true, Anomalies: 0")
		}
	})

	t.Run("Added shadow AI", func(t *testing.T) {
		report := EvaluateAnomalies(DiffReport{
			Added: []airom.Component{{Name: "Shadow", PURL: "pkg:npm/shadow"}},
		}, manifest)
		if len(report.Anomalies) != 1 || report.Anomalies[0].Type != "shadow-ai" || report.Anomalies[0].Severity != "HIGH" {
			t.Errorf("Expected shadow-ai HIGH")
		}
	})

	t.Run("Model swap", func(t *testing.T) {
		report := EvaluateAnomalies(DiffReport{
			Modified: []ComponentDelta{{OldProvider: "OpenAI GPT-4", NewProvider: "Anthropic Claude 3.5 Sonnet", ComponentID: "c1"}},
		}, manifest)
		if len(report.Anomalies) != 1 || report.Anomalies[0].Type != "model-swap" || report.Anomalies[0].Severity != "HIGH" {
			t.Errorf("Expected model-swap HIGH")
		}
	})

	t.Run("Proximity tripwire NYC LL144", func(t *testing.T) {
		report := EvaluateAnomalies(DiffReport{
			Added: []airom.Component{{
				Name:     "HiringRanker",
				Evidence: airom.Evidence{Occurrences: []airom.Occurrence{{Location: airom.Location{Path: "src/hiring/ranker.py"}}}},
				PURL:     "pkg:npm/model",
			}},
		}, manifest)
		found := false
		for _, a := range report.Anomalies {
			if a.Type == "proximity-hiring" && a.StatuteRef == "NYC LL144" && a.Severity == "HIGH" {
				found = true
			}
		}
		if !found {
			t.Errorf("Expected proximity-hiring NYC LL144 HIGH")
		}
	})

	t.Run("Proximity tripwire FCRA/ECOA", func(t *testing.T) {
		report := EvaluateAnomalies(DiffReport{
			Added: []airom.Component{{
				Name:     "Underwriter",
				Evidence: airom.Evidence{Occurrences: []airom.Occurrence{{Location: airom.Location{Path: "src/credit/underwriter.py"}}}},
				PURL:     "pkg:npm/model",
			}},
		}, manifest)
		found := false
		for _, a := range report.Anomalies {
			if a.Type == "proximity-credit" && a.StatuteRef == "FCRA/ECOA" && a.Severity == "HIGH" {
				found = true
			}
		}
		if !found {
			t.Errorf("Expected proximity-credit FCRA/ECOA HIGH")
		}
	})

	t.Run("Proximity tripwire HIPAA", func(t *testing.T) {
		report := EvaluateAnomalies(DiffReport{
			Added: []airom.Component{{
				Name:     "Diagnostics",
				Evidence: airom.Evidence{Occurrences: []airom.Occurrence{{Location: airom.Location{Path: "src/patient/diagnostics.py"}}}},
				PURL:     "pkg:npm/model",
			}},
		}, manifest)
		found := false
		for _, a := range report.Anomalies {
			if a.Type == "proximity-healthcare" && a.StatuteRef == "HIPAA/CA AB 3030" && a.Severity == "HIGH" {
				found = true
			}
		}
		if !found {
			t.Errorf("Expected proximity-healthcare HIPAA HIGH")
		}
	})

	t.Run("Parameter drift", func(t *testing.T) {
		report := EvaluateAnomalies(DiffReport{
			Modified: []ComponentDelta{{
				ComponentID: "config",
				PURL:        "pkg:npm/config",
				ParamDeltas: map[string]ParamDelta{
					"temperature": {OldValue: "0.2", NewValue: "0.9"},
				},
			}},
		}, manifest)

		if len(report.Anomalies) != 1 || report.Anomalies[0].Type != "config-drift" || report.Anomalies[0].Severity != "MEDIUM" {
			t.Errorf("Expected config-drift MEDIUM, got %v", report.Anomalies)
		}
	})
}
