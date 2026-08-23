package regwatch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegWatch_BuiltinBaselines(t *testing.T) {
	svc := NewService(DefaultScraperConfig())

	jurisdictions := []Jurisdiction{
		JurisdictionColorado,
		JurisdictionCalifornia,
		JurisdictionNYC,
		JurisdictionEU,
		JurisdictionIllinois,
		JurisdictionTexas,
		JurisdictionVirginia,
		JurisdictionUSFederal,
	}

	for _, j := range jurisdictions {
		doc, found := svc.GetCachedDocument(j)
		if !found {
			t.Fatalf("expected cached document for %s", j)
		}
		if len(doc.Sections) == 0 {
			t.Errorf("%s: expected non-empty statutory sections", j)
		}
		if doc.DocumentHash == "" {
			t.Errorf("%s: expected calculated document hash", j)
		}
	}
}

func TestRegWatch_DiffEngine_BreakingChangeDetection(t *testing.T) {
	diffEngine := NewDiffEngine()

	oldDoc := StatutoryDocument{
		Jurisdiction: JurisdictionColorado,
		Title:        "CO SB 24-205 Baseline",
		Version:      "2026.1",
		Sections: []StatuteSection{
			{
				ID:      "6-1-1703(1)(a)",
				Title:   "Duty of Reasonable Care",
				Content: "Deployers shall exercise reasonable care to prevent algorithmic discrimination.",
			},
		},
	}
	oldDoc.ComputeHash()

	// New version introduces mandatory annual third-party bias audit requirement
	newDoc := StatutoryDocument{
		Jurisdiction: JurisdictionColorado,
		Title:        "CO SB 24-205 Amended",
		Version:      "2026.2",
		Sections: []StatuteSection{
			{
				ID:      "6-1-1703(1)(a)",
				Title:   "Duty of Reasonable Care",
				Content: "Deployers shall exercise reasonable care to prevent algorithmic discrimination, and must submit to mandatory annual third-party audit under penalty of statutory fine.",
			},
			{
				ID:      "6-1-1703(1)(d)",
				Title:   "Real-Time Telemetry Disclosures",
				Content: "Deployers shall provide real-time telemetry of algorithmic risk scores to the state Attorney General.",
			},
		},
	}
	newDoc.ComputeHash()

	diff := diffEngine.ComputeDiff(oldDoc, newDoc)

	if !diff.HasChanges {
		t.Fatal("expected diff to report changes")
	}
	if diff.MaxSeverity != SeverityBreaking {
		t.Errorf("expected max severity BREAKING, got %s", diff.MaxSeverity)
	}
	if len(diff.SectionDeltas) != 2 {
		t.Fatalf("expected 2 section deltas, got %d", len(diff.SectionDeltas))
	}

	if len(diff.ImpactedRulepacks) == 0 || diff.ImpactedRulepacks[0] != "rules/compliance/co-sb-24-205.yaml" {
		t.Errorf("expected impacted rulepack rules/compliance/co-sb-24-205.yaml, got %v", diff.ImpactedRulepacks)
	}
}

func TestRegWatch_LiveScraper_MockServerAndAlerts(t *testing.T) {
	// 1. Setup mock regulatory feed server
	mockFeedDoc := StatutoryDocument{
		Jurisdiction:  JurisdictionNYC,
		Title:         "NYC Local Law 144 Emergency Amendment",
		SourceURL:     "https://mock-dcwp.nyc.gov/feed.json",
		Version:       "2026.3",
		EffectiveDate: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Sections: []StatuteSection{
			{
				ID:      "NYC-LL144-BIAS-AUDIT",
				Title:   "Annual Independent Bias Audit Requirement",
				Content: "Mandatory third-party bias audits shall include quarterly intersectional disparity index calculations.",
			},
		},
	}
	mockFeedDoc.ComputeHash()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockFeedDoc)
	}))
	defer server.Close()

	cfg := ScraperConfig{
		ClientTimeoutSec: 5,
		CustomEndpoints: map[Jurisdiction]string{
			JurisdictionNYC: server.URL,
		},
	}

	svc := NewService(cfg)

	alertCh := make(chan RegulatoryAlert, 1)
	svc.SubscribeAlerts(func(alert RegulatoryAlert) {
		select {
		case alertCh <- alert:
		default:
		}
	})

	diff, alert, err := svc.CheckJurisdiction(context.Background(), JurisdictionNYC)
	if err != nil {
		t.Fatalf("CheckJurisdiction failed: %v", err)
	}

	if !diff.HasChanges {
		t.Fatal("expected diff to report changes against mock server")
	}
	if alert == nil {
		t.Fatal("expected regulatory alert to be generated")
	}
	if alert.Jurisdiction != JurisdictionNYC {
		t.Errorf("expected NYC alert, got %s", alert.Jurisdiction)
	}

	select {
	case receivedAlert := <-alertCh:
		if receivedAlert.Jurisdiction != JurisdictionNYC {
			t.Errorf("expected NYC alert, got %s", receivedAlert.Jurisdiction)
		}
	case <-time.After(3 * time.Second):
		t.Error("expected asynchronous alert listener to receive alert within 3s")
	}

	// Verify alert history in service
	alerts := svc.GetAlerts()
	if len(alerts) != 1 {
		t.Errorf("expected 1 recorded alert, got %d", len(alerts))
	}
}
