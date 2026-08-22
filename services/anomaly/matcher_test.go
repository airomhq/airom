package anomaly

import (
	"testing"

	"github.com/airomhq/airom/internal/approved"
	"github.com/airomhq/airom/pkg/airom"
)

func TestEvaluateAnomalies(t *testing.T) {
	diff := DiffReport{
		Added: []airom.Component{
			{
				Name: "ShadowComponent",
				PURL: "pkg:npm/shadow",
				Evidence: airom.Evidence{
					Occurrences: []airom.Occurrence{
						{Location: airom.Location{Path: "src/app.js"}},
					},
				},
			},
			{
				Name: "HiringComponent",
				PURL: "pkg:npm/hiring",
				Evidence: airom.Evidence{
					Occurrences: []airom.Occurrence{
						{Location: airom.Location{Path: "src/resume/parser.js"}},
					},
				},
			},
			{
				Name: "CreditComponent",
				PURL: "pkg:npm/credit",
				Evidence: airom.Evidence{
					Occurrences: []airom.Occurrence{
						{Location: airom.Location{Path: "src/lending/score.js"}},
					},
				},
			},
			{
				Name: "HealthcareComponent",
				PURL: "pkg:npm/health",
				Evidence: airom.Evidence{
					Occurrences: []airom.Occurrence{
						{Location: airom.Location{Path: "src/patient/records.js"}},
					},
				},
			},
			{
				Name: "CleanComponent",
				PURL: "pkg:npm/clean",
				Evidence: airom.Evidence{
					Occurrences: []airom.Occurrence{
						{Location: airom.Location{Path: "src/util.js"}},
					},
				},
			},
		},
		Modified: []ComponentDelta{
			{
				ComponentID: "c1",
				PURL:        "pkg:npm/model",
				OldProvider: "OpenAI",
				NewProvider: "Anthropic",
			},
			{
				ComponentID: "c2",
				PURL:        "pkg:npm/config",
				ParamDeltas: map[string]ParamDelta{
					"temperature": {OldValue: "0.5", NewValue: "0.9"},
				},
			},
		},
	}

	manifest := &approved.ApprovedManifest{
		Approved: []approved.ComponentApproval{
			{PURL: "pkg:npm/hiring"},
			{PURL: "pkg:npm/credit"},
			{PURL: "pkg:npm/health"},
			{PURL: "pkg:npm/clean"},
			{
				PURL: "pkg:npm/config",
				PermittedConfig: map[string]string{
					"max_temp": "0.7",
				},
			},
		},
	}

	report := EvaluateAnomalies(diff, manifest)

	if report.Clean {
		t.Errorf("expected clean = false")
	}
	if report.HighestSeverity != "HIGH" {
		t.Errorf("expected highest severity HIGH, got %v", report.HighestSeverity)
	}

	var shadow, hiring, credit, health, swap, drift bool
	for _, a := range report.Anomalies {
		switch a.Type {
		case "shadow-ai":
			shadow = true
			if a.Severity != "HIGH" {
				t.Errorf("shadow severity")
			}
		case "proximity-hiring":
			hiring = true
			if a.Severity != "HIGH" {
				t.Errorf("hiring severity")
			}
		case "proximity-credit":
			credit = true
		case "proximity-healthcare":
			health = true
		case "model-swap":
			swap = true
		case "config-drift":
			drift = true
		}
	}

	if !shadow {
		t.Errorf("missing shadow-ai")
	}
	if !hiring {
		t.Errorf("missing proximity-hiring")
	}
	if !credit {
		t.Errorf("missing proximity-credit")
	}
	if !health {
		t.Errorf("missing proximity-healthcare")
	}
	if !swap {
		t.Errorf("missing model-swap")
	}
	if !drift {
		t.Errorf("missing config-drift")
	}
}

func TestEvaluateAnomaliesClean(t *testing.T) {
	diff := DiffReport{
		Added: []airom.Component{
			{
				Name: "CleanComponent",
				PURL: "pkg:npm/clean",
				Evidence: airom.Evidence{
					Occurrences: []airom.Occurrence{
						{Location: airom.Location{Path: "src/util.js"}},
					},
				},
			},
		},
	}

	manifest := &approved.ApprovedManifest{
		Approved: []approved.ComponentApproval{
			{PURL: "pkg:npm/clean"},
		},
	}

	report := EvaluateAnomalies(diff, manifest)
	if !report.Clean {
		t.Errorf("expected clean report")
	}
}

func TestEvaluateAnomaliesNilManifest(t *testing.T) {
	diff := DiffReport{
		Added: []airom.Component{
			{Name: "c1", PURL: "pkg:npm/c1"},
		},
		Modified: []ComponentDelta{
			{ComponentID: "c2", OldVersion: "1.0", NewVersion: "2.0"},
		},
	}
	report := EvaluateAnomalies(diff, nil)
	if report.HighestSeverity != "HIGH" { // because model-swap with version diff
		t.Errorf("expected HIGH severity for model swap")
	}
}
