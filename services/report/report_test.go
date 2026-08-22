package report

import (
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/services/compliancedb"
)

func TestCitation_GrammarAndExtraction(t *testing.T) {
	text := `
Acme Corp deploys GPT-4o at src/underwriting/scoring.py:47 [ev:aibom_01J:src/underwriting/scoring.py:47].
Also, Claude-3.5 is initialized at src/chat/agent.go:102 [ev:aibom_01J:src/chat/agent.go:102].
`
	cits := ExtractCitations(text)
	if len(cits) != 2 {
		t.Fatalf("expected 2 citations, got %d", len(cits))
	}

	if cits[0].AIBOMID != "aibom_01J" || cits[0].FilePath != "src/underwriting/scoring.py" || cits[0].LineNumber != 47 {
		t.Errorf("unexpected citation 0: %+v", cits[0])
	}
	if cits[1].AIBOMID != "aibom_01J" || cits[1].FilePath != "src/chat/agent.go" || cits[1].LineNumber != 102 {
		t.Errorf("unexpected citation 1: %+v", cits[1])
	}
}

func TestCitation_ValidEvidenceGrounding(t *testing.T) {
	evidenceIndex := map[EvidenceKey]EvidenceRef{
		"src/scoring.py:47": {
			AIBOMID:     "aibom-001",
			FilePath:    "src/scoring.py",
			LineNumber:  47,
			ComponentID: "comp-gpt4",
			ModelName:   "gpt-4o",
			Kind:        "hosted-model",
			Confidence:  0.98,
		},
	}

	prose := "Acme deploys gpt-4o for credit scoring [ev:aibom-001:src/scoring.py:47]."
	res := ValidateReportCitations(prose, evidenceIndex)

	if res.ValidCount != 1 || res.InvalidCount != 0 || res.UncitedClaims != 0 {
		t.Errorf("expected 1 valid, 0 invalid, 0 uncited; got valid=%d, invalid=%d, uncited=%d",
			res.ValidCount, res.InvalidCount, res.UncitedClaims)
	}
	if res.AttestationStatus != StatusVerified {
		t.Errorf("expected status VERIFIED, got %s", res.AttestationStatus)
	}
	if strings.Contains(res.CleanedProse, "[INVALID") {
		t.Errorf("prose should not contain invalid marker: %s", res.CleanedProse)
	}
}

func TestCitation_InvalidEvidenceStripped(t *testing.T) {
	evidenceIndex := map[EvidenceKey]EvidenceRef{
		"src/scoring.py:47": {
			AIBOMID:    "aibom-001",
			FilePath:   "src/scoring.py",
			LineNumber: 47,
			ModelName:  "gpt-4o",
		},
	}

	// Citation pointing to nonexistent line 999
	prose := "Acme deploys gpt-4o for risk assessment [ev:aibom-001:src/scoring.py:999]."
	res := ValidateReportCitations(prose, evidenceIndex)

	if res.InvalidCount != 1 || res.ValidCount != 0 {
		t.Errorf("expected 1 invalid, 0 valid; got valid=%d, invalid=%d", res.ValidCount, res.InvalidCount)
	}
	if res.AttestationStatus != StatusInvalidCitationRemoved {
		t.Errorf("expected status INVALID_CITATION_REMOVED, got %s", res.AttestationStatus)
	}
	if !strings.Contains(res.CleanedProse, "> [INVALID CITATION REMOVED]") {
		t.Errorf("expected invalid marker in cleaned prose: %s", res.CleanedProse)
	}
}

func TestCitation_UncitedFactualClaimAnnotated(t *testing.T) {
	evidenceIndex := map[EvidenceKey]EvidenceRef{}

	prose := "The application utilizes high-risk algorithmic scoring to approve loan applications."
	res := ValidateReportCitations(prose, evidenceIndex)

	if res.UncitedClaims != 1 {
		t.Errorf("expected 1 uncited claim, got %d", res.UncitedClaims)
	}
	if res.AttestationStatus != StatusRequiresAttestation {
		t.Errorf("expected REQUIRES_MANUAL_ATTESTATION, got %s", res.AttestationStatus)
	}
	if !strings.Contains(res.CleanedProse, "> [MANUAL ATTESTATION REQUIRED]") {
		t.Errorf("expected manual attestation marker: %s", res.CleanedProse)
	}
}

func TestColoradoReport_EndToEndGeneration(t *testing.T) {
	evIndex := map[EvidenceKey]EvidenceRef{
		"src/models/credit.py:25": {
			AIBOMID:     "aibom-co-1",
			FilePath:    "src/models/credit.py",
			LineNumber:  25,
			ComponentID: "comp-1",
			ModelName:   "openai/gpt-4o",
			Kind:        "hosted-model",
			Confidence:  0.99,
		},
		"src/nlp/classifier.py:50": {
			AIBOMID:     "aibom-co-1",
			FilePath:    "src/nlp/classifier.py",
			LineNumber:  50,
			ComponentID: "comp-2",
			ModelName:   "claude-3-5-sonnet",
			Kind:        "hosted-model",
			Confidence:  0.95,
		},
	}

	evals := []compliancedb.ControlEvaluation{
		{
			ID:         "eval-1",
			ControlID:  "co.ai-act.impact-assessment",
			StatuteRef: "CO SB 24-205 § 6-1-1703",
			Verdict:    compliancedb.VerdictMet,
		},
		{
			ID:         "eval-2",
			ControlID:  "co.ai-act.bias-mitigation",
			StatuteRef: "CO SB 24-205 § 6-1-1703(1)(b)",
			Verdict:    compliancedb.VerdictMet,
		},
	}

	snap := compliancedb.NewSnapshot(
		"snap-co-01",
		"repo-credit-system",
		"commit-co-abc",
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
		OrgID:         "org-acme",
		OrgName:       "Acme Financial Services LLC",
		RepoID:        "repo-credit-system",
		RepoName:      "credit-scoring-pipeline",
		CommitSHA:     "commit-co-abc",
		Framework:     "colorado-ai-act",
		Snapshot:      &snap,
		Evaluations:   evals,
		EvidenceIndex: evIndex,
		SignerName:    "Jane Doe",
		SignerTitle:   "Chief Risk Officer",
	}

	report, err := GenerateColoradoReport(req)
	if err != nil {
		t.Fatalf("failed to generate Colorado report: %v", err)
	}

	if report.Framework != "colorado-ai-act" || !report.AllCitationsValid {
		t.Errorf("unexpected report state: framework=%s, allValid=%v", report.Framework, report.AllCitationsValid)
	}
	if len(report.Sections) != 5 {
		t.Errorf("expected 5 report sections, got %d", len(report.Sections))
	}
	if !strings.Contains(report.ExecutiveSummary, "Acme Financial Services") && !strings.Contains(report.Title, "credit-scoring-pipeline") {
		t.Errorf("unexpected title/summary: %+v", report)
	}

	// Test Markdown Export
	md := RenderMarkdown(report)
	if !strings.Contains(md, "Colorado AI Act") || !strings.Contains(md, "Evidence Footnotes") {
		t.Errorf("unexpected markdown export: %s", md)
	}

	// Test HTML Export
	html := RenderHTML(report)
	if !strings.Contains(html, "<!DOCTYPE html>") || !strings.Contains(html, "VERIFIED") {
		t.Errorf("unexpected HTML export: %s", html)
	}

	// Test JSON Export
	jsonBytes, err := RenderJSON(report)
	if err != nil || len(jsonBytes) == 0 {
		t.Fatalf("failed to render JSON: %v", err)
	}
}

func BenchmarkCitation_ExtractionAndVerification(b *testing.B) {
	prose := `
Underwriting system deploys GPT-4o at src/scoring.py:47 [ev:aibom-1:src/scoring.py:47].
Risk scoring pipeline utilizes Claude-3.5 at src/nlp/agent.py:100 [ev:aibom-1:src/nlp/agent.py:100].
The system operates within defined parameter boundaries and logging protocols.
`
	evidence := map[EvidenceKey]EvidenceRef{
		"src/scoring.py:47": {
			AIBOMID:    "aibom-1",
			FilePath:   "src/scoring.py",
			LineNumber: 47,
			ModelName:  "gpt-4o",
		},
		"src/nlp/agent.py:100": {
			AIBOMID:    "aibom-1",
			FilePath:   "src/nlp/agent.py",
			LineNumber: 100,
			ModelName:  "claude-3.5",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateReportCitations(prose, evidence)
	}
}

func BenchmarkReport_GenerationAndExport(b *testing.B) {
	evIndex := map[EvidenceKey]EvidenceRef{
		"src/scoring.py:47": {
			AIBOMID:    "aibom-1",
			FilePath:   "src/scoring.py",
			LineNumber: 47,
			ModelName:  "gpt-4o",
		},
	}
	req := ReportRequest{
		OrgName:       "Acme Bench",
		RepoID:        "bench-repo",
		CommitSHA:     "c-bench",
		EvidenceIndex: evIndex,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep, _ := GenerateColoradoReport(req)
		_ = RenderHTML(rep)
	}
}
