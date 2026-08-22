package report

import (
	"os"
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

func TestNYCLL144Report_GenerationAndFormatting(t *testing.T) {
	evIndex := map[EvidenceKey]EvidenceRef{
		"src/screening/ranker.py:32": {
			AIBOMID:     "aibom-nyc-1",
			FilePath:    "src/screening/ranker.py",
			LineNumber:  32,
			ComponentID: "comp-ranker",
			ModelName:   "candidate-ranker-xgb",
			Kind:        "local-weights",
			Confidence:  0.96,
		},
	}

	req := ReportRequest{
		OrgName:       "Gotham Talent Corp",
		RepoID:        "talent-aedt",
		RepoName:      "resume-ranker-aedt",
		CommitSHA:     "commit-nyc-123",
		EvidenceIndex: evIndex,
	}

	report, err := GenerateNYCLL144Report(req, nil)
	if err != nil {
		t.Fatalf("failed to generate NYC LL144 report: %v", err)
	}

	if report.Framework != "nyc-ll144" || len(report.Sections) != 5 {
		t.Errorf("unexpected NYC report structure: framework=%s, sections=%d", report.Framework, len(report.Sections))
	}

	md := RenderMarkdown(report)
	if !strings.Contains(md, "Four-Fifths") || !strings.Contains(md, "Selection Rate") {
		t.Errorf("expected four-fifths and selection rate in NYC markdown: %s", md)
	}

	html := RenderHTML(report)
	if !strings.Contains(html, "Automated Employment Decision Tool") {
		t.Errorf("expected AEDT reference in NYC HTML: %s", html)
	}
}

func TestCAAB2013Report_GenerationAndFormatting(t *testing.T) {
	evIndex := map[EvidenceKey]EvidenceRef{
		"data/loader.py:15": {
			AIBOMID:     "aibom-ca-1",
			FilePath:    "data/loader.py",
			LineNumber:  15,
			ComponentID: "comp-data-loader",
			ModelName:   "enterprise-finetune-corpus",
			Kind:        "dataset",
			Confidence:  0.92,
		},
	}

	req := ReportRequest{
		OrgName:       "Pacific AI Labs",
		RepoID:        "genai-writer",
		RepoName:      "enterprise-assistant-llm",
		CommitSHA:     "commit-ca-789",
		EvidenceIndex: evIndex,
	}

	report, err := GenerateCAAB2013Report(req, nil)
	if err != nil {
		t.Fatalf("failed to generate CA AB 2013 report: %v", err)
	}

	if report.Framework != "ca-ab2013" || len(report.Sections) != 4 {
		t.Errorf("unexpected CA report structure: framework=%s, sections=%d", report.Framework, len(report.Sections))
	}

	md := RenderMarkdown(report)
	if !strings.Contains(md, "California AB 2013") || !strings.Contains(md, "Personal Info Included") {
		t.Errorf("expected AB 2013 notice and privacy table in markdown: %s", md)
	}

	html := RenderHTML(report)
	if !strings.Contains(html, "Training Data Transparency Notice") {
		t.Errorf("expected transparency notice in HTML: %s", html)
	}
}

func TestEngineConfig_ValidationAndDefaults(t *testing.T) {
	cfg := DefaultEngineConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected default config to be valid, got: %v", err)
	}

	// Invalid provider
	badCfg := cfg
	badCfg.LLMBackend.Provider = "unsupported-llm"
	if err := badCfg.Validate(); err == nil {
		t.Errorf("expected error on unsupported provider")
	}

	// Missing required API key env when not air-gapped
	onlineCfg := cfg
	onlineCfg.LLMBackend.Provider = ProviderAnthropic
	onlineCfg.LLMBackend.AirGapped = false
	onlineCfg.LLMBackend.APIKeyEnv = "TEST_MISSING_API_KEY_ENV_XYZ"
	os.Unsetenv("TEST_MISSING_API_KEY_ENV_XYZ")
	if err := onlineCfg.Validate(); err == nil {
		t.Errorf("expected error on missing API key env var")
	}
}

func TestBIPAReport_GenerationAndExport(t *testing.T) {
	evIndex := map[EvidenceKey]EvidenceRef{
		"src/bio/face.py:12": {
			AIBOMID:     "aibom-il-1",
			FilePath:    "src/bio/face.py",
			LineNumber:  12,
			ComponentID: "comp-face-embed",
			ModelName:   "facenet-embeddings",
			Kind:        "local-model-file",
			Confidence:  0.97,
		},
	}
	req := ReportRequest{
		OrgName:       "Biometric Security Corp",
		RepoID:        "access-control-ai",
		RepoName:      "facial-auth-pipeline",
		CommitSHA:     "c-il-123",
		EvidenceIndex: evIndex,
	}

	rep, err := GenerateBIPAReport(req, nil)
	if err != nil {
		t.Fatalf("failed to generate BIPA report: %v", err)
	}
	if rep.Framework != "illinois-bipa" || len(rep.Sections) != 4 {
		t.Errorf("unexpected BIPA report structure: framework=%s, sections=%d", rep.Framework, len(rep.Sections))
	}
	md := RenderMarkdown(rep)
	if !strings.Contains(md, "Illinois BIPA") || !strings.Contains(md, "Retention Schedule") {
		t.Errorf("unexpected BIPA markdown: %s", md)
	}
	html := RenderHTML(rep)
	if !strings.Contains(html, "Illinois BIPA") {
		t.Errorf("unexpected BIPA HTML: %s", html)
	}
}

func TestTRAIGAReport_GenerationAndExport(t *testing.T) {
	evIndex := map[EvidenceKey]EvidenceRef{
		"src/decision/scorer.py:20": {
			AIBOMID:     "aibom-tx-1",
			FilePath:    "src/decision/scorer.py",
			LineNumber:  20,
			ComponentID: "comp-tx-scorer",
			ModelName:   "texas-gov-decision-engine",
			Kind:        "decision-system",
			Confidence:  0.95,
		},
	}
	req := ReportRequest{
		OrgName:       "Lone Star Analytics LLC",
		RepoID:        "benefits-scoring",
		RepoName:      "state-benefits-decisions",
		CommitSHA:     "c-tx-456",
		EvidenceIndex: evIndex,
	}

	rep, err := GenerateTRAIGAReport(req, nil)
	if err != nil {
		t.Fatalf("failed to generate TRAIGA report: %v", err)
	}
	if rep.Framework != "texas-traiga" || len(rep.Sections) != 3 {
		t.Errorf("unexpected TRAIGA report structure: framework=%s, sections=%d", rep.Framework, len(rep.Sections))
	}
	md := RenderMarkdown(rep)
	if !strings.Contains(md, "Texas TRAIGA") || !strings.Contains(md, "State Registry ID") {
		t.Errorf("unexpected TRAIGA markdown: %s", md)
	}
	html := RenderHTML(rep)
	if !strings.Contains(html, "Texas Responsible AI Registry") {
		t.Errorf("unexpected TRAIGA HTML: %s", html)
	}
}

func TestVCDPAReport_GenerationAndExport(t *testing.T) {
	evIndex := map[EvidenceKey]EvidenceRef{
		"src/nlp/classifier.py:30": {
			AIBOMID:     "aibom-va-1",
			FilePath:    "src/nlp/classifier.py",
			LineNumber:  30,
			ComponentID: "comp-va-nlp",
			ModelName:   "consumer-profiler-v1",
			Kind:        "hosted-llm",
			Confidence:  0.94,
		},
	}
	req := ReportRequest{
		OrgName:       "Old Dominion Data Inc",
		RepoID:        "profiling-engine",
		RepoName:      "automated-credit-profiling",
		CommitSHA:     "c-va-789",
		EvidenceIndex: evIndex,
	}

	rep, err := GenerateVCDPAReport(req, nil)
	if err != nil {
		t.Fatalf("failed to generate VCDPA report: %v", err)
	}
	if rep.Framework != "virginia-vcdpa" || len(rep.Sections) != 3 {
		t.Errorf("unexpected VCDPA report structure: framework=%s, sections=%d", rep.Framework, len(rep.Sections))
	}
	md := RenderMarkdown(rep)
	if !strings.Contains(md, "Virginia VCDPA") || !strings.Contains(md, "Opt-Out") {
		t.Errorf("unexpected VCDPA markdown: %s", md)
	}
	html := RenderHTML(rep)
	if !strings.Contains(html, "Data Protection Assessment") {
		t.Errorf("unexpected VCDPA HTML: %s", html)
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

func BenchmarkNYCLL144_Generation(b *testing.B) {
	evIndex := map[EvidenceKey]EvidenceRef{
		"src/ranker.py:10": {
			AIBOMID:    "aibom-nyc",
			FilePath:   "src/ranker.py",
			LineNumber: 10,
			ModelName:  "ranker",
		},
	}
	req := ReportRequest{
		OrgName:       "Gotham Bench",
		RepoID:        "bench-aedt",
		CommitSHA:     "c-bench",
		EvidenceIndex: evIndex,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep, _ := GenerateNYCLL144Report(req, nil)
		_ = RenderHTML(rep)
	}
}

func BenchmarkCAAB2013_Generation(b *testing.B) {
	evIndex := map[EvidenceKey]EvidenceRef{
		"data/loader.py:10": {
			AIBOMID:    "aibom-ca",
			FilePath:   "data/loader.py",
			LineNumber: 10,
			ModelName:  "corpus",
		},
	}
	req := ReportRequest{
		OrgName:       "Pacific Bench",
		RepoID:        "bench-ca",
		CommitSHA:     "c-bench",
		EvidenceIndex: evIndex,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep, _ := GenerateCAAB2013Report(req, nil)
		_ = RenderHTML(rep)
	}
}
