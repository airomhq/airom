package report

import (
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/services/compliancedb"
)

func TestEUAIAct_StatutoryCompleteness(t *testing.T) {
	evIndex := map[EvidenceKey]EvidenceRef{
		"src/underwriting/scorer.py:14": {
			AIBOMID:     "aibom-eu-1",
			FilePath:    "src/underwriting/scorer.py",
			LineNumber:  14,
			ComponentID: "comp-gpt4",
			ModelName:   "openai-gpt-4o",
			Kind:        "hosted-llm",
			Confidence:  0.98,
		},
	}

	evals := []compliancedb.ControlEvaluation{
		{
			ID:         "eval-eu-1",
			ControlID:  "eu.ai-act.title3.technical-documentation",
			StatuteRef: "Regulation (EU) 2024/1689 Art. 11",
			Verdict:    compliancedb.VerdictMet,
		},
		{
			ID:         "eval-eu-2",
			ControlID:  "eu.ai-act.title3.data-governance",
			StatuteRef: "Regulation (EU) 2024/1689 Art. 10",
			Verdict:    compliancedb.VerdictMet,
		},
	}

	snap := compliancedb.NewSnapshot(
		"snap-eu-01",
		"acme/risk-engine",
		"commit-eu-abc",
		"main",
		time.Now().UTC(),
		"aibom-sha-256",
		2,
		0,
		2,
		0,
		0,
		"",
		nil,
	)

	req := ReportRequest{
		OrgID:         "org-acme-eu",
		OrgName:       "Acme Global EU B.V.",
		RepoID:        "acme/risk-engine",
		RepoName:      "risk-decision-engine",
		CommitSHA:     "commit-eu-abc",
		Framework:     "eu-ai-act",
		Snapshot:      &snap,
		Evaluations:   evals,
		EvidenceIndex: evIndex,
		SignerName:    "Sarah Chen",
		SignerTitle:   "EU AI Compliance Officer",
	}

	report, err := GenerateEUAIActTechnicalDoc(req)
	if err != nil {
		t.Fatalf("GenerateEUAIActTechnicalDoc failed: %v", err)
	}

	if report.Framework != "eu-ai-act" {
		t.Errorf("expected framework eu-ai-act, got %s", report.Framework)
	}
	if !report.AllCitationsValid {
		t.Error("expected AllCitationsValid to be true")
	}

	// Verify mandatory 6 sections
	if len(report.Sections) != 6 {
		t.Fatalf("expected 6 statutory sections, got %d", len(report.Sections))
	}

	mandatoryRefs := []string{
		"Annex IV § 1",
		"Annex IV § 2(a)-(d)",
		"Art. 10 & Annex IV § 2(e)",
		"Art. 5, Art. 9 & Annex IV § 2(f)",
		"Art. 14, Art. 15 & Annex IV § 2(g)",
		"Annex IV § 3 & Art. 47",
	}

	for i, ref := range mandatoryRefs {
		if !strings.Contains(report.Sections[i].StatuteRef, ref) {
			t.Errorf("section %d missing mandatory statute ref %q; got %q", i, ref, report.Sections[i].StatuteRef)
		}
	}
}

func TestEUAIAct_AdversarialGrounding(t *testing.T) {
	proseWithFakeCit := "System deploys unapproved model [ev:aibom-fake:src/secret/model.py:99]."
	res := ValidateReportCitations(proseWithFakeCit, make(map[EvidenceKey]EvidenceRef))

	if !strings.Contains(res.CleanedProse, "[INVALID CITATION REMOVED]") {
		t.Error("expected invalid citation to be stripped with [INVALID CITATION REMOVED]")
	}
}

func TestEUAIAct_WCAGHTMLAccessibility(t *testing.T) {
	snap := compliancedb.NewSnapshot(
		"snap-eu-wcag",
		"acme/wcag-test",
		"commit-wcag",
		"main",
		time.Now().UTC(),
		"aibom-sha-256",
		1,
		0,
		1,
		0,
		0,
		"",
		nil,
	)

	req := ReportRequest{
		OrgID:     "org-acme",
		OrgName:   "Acme Corp",
		RepoID:    "acme/wcag-test",
		RepoName:  "wcag-test-repo",
		CommitSHA: "commit-wcag",
		Framework: "eu-ai-act",
		Snapshot:  &snap,
	}

	report, err := GenerateEUAIActTechnicalDoc(req)
	if err != nil {
		t.Fatalf("GenerateEUAIActTechnicalDoc failed: %v", err)
	}

	html := report.RenderEUAIActHTML()

	if !strings.HasPrefix(strings.TrimSpace(html), "<!DOCTYPE html>") {
		t.Error("missing standard DOCTYPE")
	}
	if !strings.Contains(html, `<html lang="en">`) {
		t.Error("missing lang=en attribute")
	}
	if !strings.Contains(html, `<header>`) || !strings.Contains(html, `<main>`) || !strings.Contains(html, `<footer>`) {
		t.Error("missing semantic landmarks header/main/footer")
	}
	if !strings.Contains(html, `aria-label="System Metadata"`) {
		t.Error("missing accessibility aria-label on metadata block")
	}
}
