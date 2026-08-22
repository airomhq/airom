package report

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/services/compliancedb"
)

// TestQA_AdversarialHallucinationStripping tests AIROM ReportEngine's grounding verification
// against adversarial LLM hallucinations, fabricated file paths, forged AIBOM IDs,
// line number mismatches, and uncited high-risk deployment assertions.
func TestQA_AdversarialHallucinationStripping(t *testing.T) {
	// Baseline Ground Truth Evidence Index
	groundTruthIndex := map[EvidenceKey]EvidenceRef{
		"src/underwriting/credit_scorer.py:45": {
			AIBOMID:     "aibom-auth-001",
			FilePath:    "src/underwriting/credit_scorer.py",
			LineNumber:  45,
			ComponentID: "comp-xgboost-v1",
			ModelName:   "xgboost-classifier",
			Kind:        "embedded-model",
			Confidence:  0.99,
		},
		"src/chat/support_bot.py:112": {
			AIBOMID:     "aibom-auth-002",
			FilePath:    "src/chat/support_bot.py",
			LineNumber:  112,
			ComponentID: "comp-gpt4o",
			ModelName:   "openai/gpt-4o-mini",
			Kind:        "hosted-model",
			Confidence:  0.97,
		},
	}

	t.Run("Adversarial_FabricatedPathAndForgedAIBOM", func(t *testing.T) {
		adversarialProse := "The underwriting pipeline executes inference via secret model at src/nonexistent/secret_algo.py:42 [ev:aibom_forged_999:src/nonexistent/secret_algo.py:42]."

		result := ValidateReportCitations(adversarialProse, groundTruthIndex)

		if result.InvalidCount != 1 {
			t.Fatalf("expected 1 invalid citation detected, got %d", result.InvalidCount)
		}
		if result.ValidCount != 0 {
			t.Fatalf("expected 0 valid citations, got %d", result.ValidCount)
		}
		if result.AttestationStatus != StatusInvalidCitationRemoved {
			t.Fatalf("expected status %s, got %s", StatusInvalidCitationRemoved, result.AttestationStatus)
		}
		if !strings.Contains(result.CleanedProse, "> [INVALID CITATION REMOVED]") {
			t.Errorf("expected cleaned prose to contain invalid citation marker, got: %s", result.CleanedProse)
		}
		if !strings.Contains(result.CleanedProse, "[UNVERIFIED CLAIM REMOVED]") {
			t.Errorf("expected hallucinated citation tag to be replaced with [UNVERIFIED CLAIM REMOVED], got: %s", result.CleanedProse)
		}
		if strings.Contains(result.CleanedProse, "aibom_forged_999") {
			t.Errorf("forged AIBOM tag must not persist in cleaned output: %s", result.CleanedProse)
		}
	})

	t.Run("Adversarial_HallucinatedLineNumberOnRealFile", func(t *testing.T) {
		// Target real file but hallucinated line number 999
		adversarialProse := "System utilizes classifier at src/underwriting/credit_scorer.py:999 [ev:aibom-auth-001:src/underwriting/credit_scorer.py:999]."

		result := ValidateReportCitations(adversarialProse, groundTruthIndex)

		if result.InvalidCount != 1 {
			t.Fatalf("expected 1 invalid citation, got %d", result.InvalidCount)
		}
		if result.ValidCount != 0 {
			t.Fatalf("expected 0 valid citations, got %d", result.ValidCount)
		}
		if result.ExtractedCitations[0].IsValid {
			t.Errorf("hallucinated line number citation must be marked invalid")
		}
		if !strings.Contains(result.CleanedProse, "> [INVALID CITATION REMOVED]") {
			t.Errorf("expected invalid marker for wrong line number: %s", result.CleanedProse)
		}
	})

	t.Run("Adversarial_UncitedFactualDeploymentAssertions", func(t *testing.T) {
		claims := []string{
			"The scoring engine deploys an algorithmic decision system for credit evaluation.",
			"The service utilizes gpt-4o for high-risk loan approvals.",
			"The application implements claude-3.5 for automated tenant screening.",
			"System executes automated inference across production endpoint.",
			"The framework configured with model weights without governance review.",
		}

		for _, claim := range claims {
			res := ValidateReportCitations(claim, groundTruthIndex)
			if res.UncitedClaims != 1 {
				t.Errorf("claim '%s' should be flagged as uncited claim, got %d", claim, res.UncitedClaims)
			}
			if res.AttestationStatus != StatusRequiresAttestation {
				t.Errorf("expected status %s for uncited claim, got %s", StatusRequiresAttestation, res.AttestationStatus)
			}
			if !strings.Contains(res.CleanedProse, "> [MANUAL ATTESTATION REQUIRED]") {
				t.Errorf("expected manual attestation prefix for claim '%s', got: %s", claim, res.CleanedProse)
			}
		}
	})

	t.Run("Adversarial_MixedValidHallucinatedAndUncitedClaims", func(t *testing.T) {
		adversarialInput := strings.Join([]string{
			"# Section 1: System Overview",
			"The following report summarizes production AI deployments.",
			"",
			"Credit underwriting deploys xgboost at src/underwriting/credit_scorer.py:45 [ev:aibom-auth-001:src/underwriting/credit_scorer.py:45].",
			"Fraud detection deploys gemini-3.0-ultra at src/nonexistent/secret_algo.py:42 [ev:aibom_fake_999:src/nonexistent/secret_algo.py:42].",
			"The scoring engine executes algorithmic decision system evaluation for credit limits.",
			"Customer support utilizes gpt-4o-mini at src/chat/support_bot.py:112 [ev:aibom-auth-002:src/chat/support_bot.py:112].",
			"---",
		}, "\n")

		result := ValidateReportCitations(adversarialInput, groundTruthIndex)

		// 2 valid citations (credit_scorer:45, support_bot:112)
		// 1 invalid hallucinated citation (secret_algo.py:42)
		// 1 uncited factual claim (scoring engine executes algorithmic decision system...)
		if result.ValidCount != 2 {
			t.Errorf("expected 2 valid citations, got %d", result.ValidCount)
		}
		if result.InvalidCount != 1 {
			t.Errorf("expected 1 invalid citation, got %d", result.InvalidCount)
		}
		if result.UncitedClaims != 1 {
			t.Errorf("expected 1 uncited claim, got %d", result.UncitedClaims)
		}
		// Invalid citations take precedence in overall AttestationStatus
		if result.AttestationStatus != StatusInvalidCitationRemoved {
			t.Errorf("expected status %s, got %s", StatusInvalidCitationRemoved, result.AttestationStatus)
		}

		// Verify 100% detection and proper annotation in prose
		lines := strings.Split(result.CleanedProse, "\n")
		var hasValidCredit, hasValidSupport, hasStrippedFraud, hasFlaggedUncited bool

		for _, l := range lines {
			if strings.Contains(l, "credit_scorer.py:45") && !strings.HasPrefix(l, ">") {
				hasValidCredit = true
			}
			if strings.Contains(l, "support_bot.py:112") && !strings.HasPrefix(l, ">") {
				hasValidSupport = true
			}
			if strings.HasPrefix(l, "> [INVALID CITATION REMOVED]") && strings.Contains(l, "Fraud detection") {
				hasStrippedFraud = true
			}
			if strings.HasPrefix(l, "> [MANUAL ATTESTATION REQUIRED]") && strings.Contains(l, "scoring engine executes") {
				hasFlaggedUncited = true
			}
		}

		if !hasValidCredit {
			t.Errorf("valid credit citation should remain unstripped")
		}
		if !hasValidSupport {
			t.Errorf("valid support bot citation should remain unstripped")
		}
		if !hasStrippedFraud {
			t.Errorf("hallucinated fraud detection citation must be stripped with [INVALID CITATION REMOVED]")
		}
		if !hasFlaggedUncited {
			t.Errorf("uncited claim must be flagged with [MANUAL ATTESTATION REQUIRED]")
		}
	})
}

// TestQA_ColoradoStatutoryCompleteness verifies that Colorado AI Act reports
// comprehensively satisfy all statutory mandates under CO SB 24-205 § 6-1-1703
// (subsections 1(a), 1(b), 1(c), (2), and (4)).
func TestQA_ColoradoStatutoryCompleteness(t *testing.T) {
	evidenceIndex := map[EvidenceKey]EvidenceRef{
		"src/models/underwriting.py:30": {
			AIBOMID:     "aibom-co-001",
			FilePath:    "src/models/underwriting.py",
			LineNumber:  30,
			ComponentID: "comp-co-risk",
			ModelName:   "openai/gpt-4o",
			Kind:        "hosted-model",
			Confidence:  0.99,
		},
	}

	evaluations := []compliancedb.ControlEvaluation{
		{
			ID:         "eval-co-01",
			ControlID:  "co.ai-act.inventory",
			StatuteRef: "CO SB 24-205 § 6-1-1703(1)(a)",
			Verdict:    compliancedb.VerdictMet,
		},
		{
			ID:         "eval-co-02",
			ControlID:  "co.ai-act.bias-safeguards",
			StatuteRef: "CO SB 24-205 § 6-1-1703(1)(b)",
			Verdict:    compliancedb.VerdictGap,
			GapMessage: "Missing affirmative bias mitigation audit for demographic group parity in consequential decisions.",
		},
		{
			ID:         "eval-co-03",
			ControlID:  "co.ai-act.data-transparency",
			StatuteRef: "CO SB 24-205 § 6-1-1703(1)(c)",
			Verdict:    compliancedb.VerdictMet,
		},
		{
			ID:         "eval-co-04",
			ControlID:  "co.ai-act.continuous-monitoring",
			StatuteRef: "CO SB 24-205 § 6-1-1703(2)",
			Verdict:    compliancedb.VerdictMet,
		},
		{
			ID:         "eval-co-05",
			ControlID:  "co.ai-act.executive-attestation",
			StatuteRef: "CO SB 24-205 § 6-1-1703(4)",
			Verdict:    compliancedb.VerdictManual,
		},
	}

	snapshot := compliancedb.NewSnapshot(
		"snap-co-qa-999",
		"repo-colorado-governance",
		"sha256-commit-deadbeef",
		"main",
		time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC),
		"sha256-aibom-ledger-root-hash",
		1,
		1,
		4,
		0,
		0,
		"sha256-prev-snapshot-link",
		nil,
	)

	req := ReportRequest{
		OrgID:         "org-co-enterprise",
		OrgName:       "Colorado Financial & Risk Systems Inc.",
		RepoID:        "repo-colorado-governance",
		RepoName:      "colorado-governance-service",
		CommitSHA:     "sha256-commit-deadbeef",
		Framework:     "colorado-ai-act",
		Snapshot:      &snapshot,
		Evaluations:   evaluations,
		EvidenceIndex: evidenceIndex,
		SignerName:    "Dr. Evelyn Vance",
		SignerTitle:   "Chief AI Ethics & Compliance Officer",
	}

	report, err := GenerateColoradoReport(req)
	if err != nil {
		t.Fatalf("GenerateColoradoReport failed: %v", err)
	}

	t.Run("Verify_TopLevelReportMetadata", func(t *testing.T) {
		if report.Framework != "colorado-ai-act" {
			t.Errorf("expected framework colorado-ai-act, got %s", report.Framework)
		}
		if report.OrgName != "Colorado Financial & Risk Systems Inc." {
			t.Errorf("expected org name 'Colorado Financial & Risk Systems Inc.', got '%s'", report.OrgName)
		}
		if report.RepoName != "colorado-governance-service" {
			t.Errorf("expected repo name 'colorado-governance-service', got '%s'", report.RepoName)
		}
		if report.CommitSHA != "sha256-commit-deadbeef" {
			t.Errorf("expected commit sha 'sha256-commit-deadbeef', got '%s'", report.CommitSHA)
		}
		if report.SignerName != "Dr. Evelyn Vance" {
			t.Errorf("expected signer name 'Dr. Evelyn Vance', got '%s'", report.SignerName)
		}
		if report.SignerTitle != "Chief AI Ethics & Compliance Officer" {
			t.Errorf("expected signer title 'Chief AI Ethics & Compliance Officer', got '%s'", report.SignerTitle)
		}

		if report.Metadata["statute"] != "Colorado SB 24-205" {
			t.Errorf("expected metadata statute 'Colorado SB 24-205', got '%s'", report.Metadata["statute"])
		}
		if report.Metadata["jurisdiction"] != "State of Colorado, USA" {
			t.Errorf("expected metadata jurisdiction 'State of Colorado, USA', got '%s'", report.Metadata["jurisdiction"])
		}
		if report.Metadata["effective_date"] != "2026-02-01" {
			t.Errorf("expected metadata effective_date '2026-02-01', got '%s'", report.Metadata["effective_date"])
		}
	})

	t.Run("Verify_FiveStatutorySectionsCompleteness", func(t *testing.T) {
		if len(report.Sections) != 5 {
			t.Fatalf("expected exactly 5 statutory sections, got %d", len(report.Sections))
		}

		statutoryMandates := map[string]struct {
			ExpectedID         string
			ExpectedStatuteRef string
			TitleKeyword       string
			RequiredProseSub   string
		}{
			"1(a)": {
				ExpectedID:         "sec-01-inventory",
				ExpectedStatuteRef: "CO SB 24-205 § 6-1-1703(1)(a)",
				TitleKeyword:       "Inventory",
				RequiredProseSub:   "CO SB 24-205 § 6-1-1703(1)(a)",
			},
			"1(b)": {
				ExpectedID:         "sec-02-bias-risk",
				ExpectedStatuteRef: "CO SB 24-205 § 6-1-1703(1)(b)",
				TitleKeyword:       "Algorithmic Discrimination",
				RequiredProseSub:   "CO SB 24-205 § 6-1-1703(1)(b)",
			},
			"1(c)": {
				ExpectedID:         "sec-03-data-transparency",
				ExpectedStatuteRef: "CO SB 24-205 § 6-1-1703(1)(c)",
				TitleKeyword:       "Training Data",
				RequiredProseSub:   "CO SB 24-205 § 6-1-1703(1)(c)",
			},
			"(2)": {
				ExpectedID:         "sec-04-monitoring",
				ExpectedStatuteRef: "CO SB 24-205 § 6-1-1703(2)",
				TitleKeyword:       "Monitoring",
				RequiredProseSub:   "CO SB 24-205 § 6-1-1703(2)",
			},
			"(4)": {
				ExpectedID:         "sec-05-attestation",
				ExpectedStatuteRef: "CO SB 24-205 § 6-1-1703(4)",
				TitleKeyword:       "Attestation",
				RequiredProseSub:   "CO SB 24-205 § 6-1-1703(4)",
			},
		}

		for idx, sec := range report.Sections {
			var mandateKey string
			switch idx {
			case 0:
				mandateKey = "1(a)"
			case 1:
				mandateKey = "1(b)"
			case 2:
				mandateKey = "1(c)"
			case 3:
				mandateKey = "(2)"
			case 4:
				mandateKey = "(4)"
			}

			expected := statutoryMandates[mandateKey]
			if sec.ID != expected.ExpectedID {
				t.Errorf("section %d: expected ID '%s', got '%s'", idx, expected.ExpectedID, sec.ID)
			}
			if sec.StatuteRef != expected.ExpectedStatuteRef {
				t.Errorf("section %d: expected StatuteRef '%s', got '%s'", idx, expected.ExpectedStatuteRef, sec.StatuteRef)
			}
			if !strings.Contains(sec.Title, expected.TitleKeyword) {
				t.Errorf("section %d: title '%s' does not contain keyword '%s'", idx, sec.Title, expected.TitleKeyword)
			}
			if !strings.Contains(sec.Prose, expected.RequiredProseSub) && sec.ID != "sec-05-attestation" {
				t.Errorf("section %d: prose does not reference statute '%s'", idx, expected.RequiredProseSub)
			}
		}
	})

	t.Run("Verify_ComplianceGapCalloutsInSection2", func(t *testing.T) {
		sec2 := report.Sections[1]
		if !strings.Contains(sec2.Prose, "> [COMPLIANCE GAP DETECTED]") {
			t.Errorf("expected Section 2 to contain compliance gap callout, got:\n%s", sec2.Prose)
		}
		if !strings.Contains(sec2.Prose, "co.ai-act.bias-safeguards") {
			t.Errorf("expected Section 2 to mention control ID 'co.ai-act.bias-safeguards'")
		}
		if !strings.Contains(sec2.Prose, "Missing affirmative bias mitigation audit") {
			t.Errorf("expected Section 2 to contain gap message details")
		}
	})

	t.Run("Verify_LedgerSnapshotIntegrityInSection4", func(t *testing.T) {
		sec4 := report.Sections[3]
		if !strings.Contains(sec4.Prose, "snap-co-qa-999") {
			t.Errorf("expected Section 4 to contain snapshot ID 'snap-co-qa-999'")
		}
		if !strings.Contains(sec4.Prose, snapshot.SelfHash) {
			t.Errorf("expected Section 4 to contain cryptographic self hash '%s'", snapshot.SelfHash)
		}
		if !strings.Contains(sec4.Prose, "sha256-prev-snapshot-link") {
			t.Errorf("expected Section 4 to contain parent link hash")
		}
	})

	t.Run("Verify_ExecutiveAttestationSignatureDetails", func(t *testing.T) {
		sec5 := report.Sections[4]
		if !strings.Contains(sec5.Prose, "Dr. Evelyn Vance") {
			t.Errorf("expected Section 5 to include signer name 'Dr. Evelyn Vance'")
		}
		if !strings.Contains(sec5.Prose, "Chief AI Ethics & Compliance Officer") {
			t.Errorf("expected Section 5 to include signer title 'Chief AI Ethics & Compliance Officer'")
		}
		if !strings.Contains(sec5.Prose, "/s/ Dr. Evelyn Vance") {
			t.Errorf("expected Section 5 to contain digital signature line")
		}
		if !strings.Contains(sec5.Prose, "colorado-governance-service") {
			t.Errorf("expected Section 5 to cite repository name")
		}
		if !strings.Contains(sec5.Prose, "sha256-commit-deadbeef") {
			t.Errorf("expected Section 5 to cite commit SHA")
		}
	})

	t.Run("Verify_SignerDefaultsFallback", func(t *testing.T) {
		reqDefault := ReportRequest{
			RepoID: "repo-default",
		}
		repDef, err := GenerateColoradoReport(reqDefault)
		if err != nil {
			t.Fatalf("failed to generate default report: %v", err)
		}
		if repDef.SignerName != "Chief Compliance & AI Governance Officer" {
			t.Errorf("expected default signer name, got '%s'", repDef.SignerName)
		}
		if repDef.SignerTitle != "Authorized AI Deployer Representative" {
			t.Errorf("expected default signer title, got '%s'", repDef.SignerTitle)
		}
	})
}

// TestQA_WCAGAccessibilityCompliance verifies that RenderHTML produces
// strict WCAG 2.1 AA compliant accessible HTML output.
func TestQA_WCAGAccessibilityCompliance(t *testing.T) {
	evidenceIndex := map[EvidenceKey]EvidenceRef{
		"src/scoring.py:50": {
			AIBOMID:     "aibom-wcag-01",
			FilePath:    "src/scoring.py",
			LineNumber:  50,
			ComponentID: "comp-scorer",
			ModelName:   "openai/gpt-4o",
			Kind:        "hosted-model",
			Confidence:  0.98,
		},
	}

	evals := []compliancedb.ControlEvaluation{
		{
			ID:         "eval-wcag-1",
			ControlID:  "co.ai-act.inventory",
			StatuteRef: "CO SB 24-205 § 6-1-1703(1)(a)",
			Verdict:    compliancedb.VerdictMet,
		},
	}

	req := ReportRequest{
		OrgName:       "Accessibility First Corp & Partners <Test>",
		RepoName:      "accessible-model-repo",
		CommitSHA:     "commit-wcag-12345",
		EvidenceIndex: evidenceIndex,
		Evaluations:   evals,
		SignerName:    "Alice Walker",
		SignerTitle:   "VP Compliance",
	}

	report, err := GenerateColoradoReport(req)
	if err != nil {
		t.Fatalf("failed to generate report: %v", err)
	}

	htmlContent := RenderHTML(report)

	t.Run("WCAG_ValidDocTypeAndHtmlLang", func(t *testing.T) {
		if !strings.HasPrefix(strings.TrimSpace(htmlContent), "<!DOCTYPE html>") {
			t.Errorf("document must begin with '<!DOCTYPE html>'")
		}
		if !strings.Contains(htmlContent, "<html lang=\"en\">") {
			t.Errorf("root element must specify lang attribute '<html lang=\"en\">'")
		}
	})

	t.Run("WCAG_MetaTagsCharsetAndViewport", func(t *testing.T) {
		if !strings.Contains(htmlContent, "<meta charset=\"UTF-8\">") {
			t.Errorf("document must specify UTF-8 charset meta tag")
		}
		if !strings.Contains(htmlContent, "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">") {
			t.Errorf("document must specify responsive viewport meta tag")
		}
	})

	t.Run("WCAG_PageTitlePresentAndEscaped", func(t *testing.T) {
		titleRegex := regexp.MustCompile(`<title>(.*?)</title>`)
		matches := titleRegex.FindStringSubmatch(htmlContent)
		if len(matches) < 2 || strings.TrimSpace(matches[1]) == "" {
			t.Fatalf("document must contain non-empty <title> tag")
		}
		if strings.Contains(matches[1], "<") || strings.Contains(matches[1], ">") {
			t.Errorf("title tag content should have escaped HTML entities: %s", matches[1])
		}
	})

	t.Run("WCAG_SemanticLandmarksAndContainers", func(t *testing.T) {
		requiredLandmarks := []string{
			"<header>",
			"</header>",
			"<main>",
			"</main>",
			"<section class=\"summary-box\">",
			"</section>",
			"<article class=\"section\">",
			"</article>",
		}

		for _, tag := range requiredLandmarks {
			if !strings.Contains(htmlContent, tag) {
				t.Errorf("expected semantic HTML landmark tag '%s' not found", tag)
			}
		}
	})

	t.Run("WCAG_HeadingHierarchyAndStructure", func(t *testing.T) {
		// Verify single H1 tag inside header
		h1Regex := regexp.MustCompile(`<h1[^>]*>(.*?)</h1>`)
		h1Matches := h1Regex.FindAllStringSubmatch(htmlContent, -1)
		if len(h1Matches) != 1 {
			t.Errorf("expected exactly 1 <h1> tag on page, found %d", len(h1Matches))
		}

		// Verify H2 tags exist for sections
		h2Regex := regexp.MustCompile(`<h2[^>]*>(.*?)</h2>`)
		h2Matches := h2Regex.FindAllStringSubmatch(htmlContent, -1)
		if len(h2Matches) < 5 {
			t.Errorf("expected at least 5 <h2> tags for report sections, found %d", len(h2Matches))
		}
	})

	t.Run("WCAG_TableAccessibilityAttributes", func(t *testing.T) {
		if !strings.Contains(htmlContent, "<table class=\"evidence-table\" aria-label=\"Evidence Grounding Table\">") {
			t.Errorf("evidence table must have aria-label attribute for screen readers")
		}
		if !strings.Contains(htmlContent, "<thead><tr><th>Citation Tag</th><th>Source File</th><th>Line</th><th>Verification Status</th></tr></thead>") {
			t.Errorf("table must contain explicit semantic <thead> with <th> column headers")
		}
		if !strings.Contains(htmlContent, "<tbody>") || !strings.Contains(htmlContent, "</tbody>") {
			t.Errorf("table must contain semantic <tbody> container")
		}
	})

	t.Run("WCAG_PrintStylesheetAndContrastBadges", func(t *testing.T) {
		if !strings.Contains(htmlContent, "@media print") {
			t.Errorf("expected print stylesheet @media print media query")
		}
		if !strings.Contains(htmlContent, ".badge-verified") {
			t.Errorf("expected .badge-verified CSS class")
		}
		if !strings.Contains(htmlContent, ".badge-gap") {
			t.Errorf("expected .badge-gap CSS class")
		}
	})

	t.Run("WCAG_HTMLEscapingSafety", func(t *testing.T) {
		// Org name in request contained "<Test>" and "&"
		if strings.Contains(htmlContent, "<Test>") {
			t.Errorf("unencoded HTML tags '<Test>' found in output, potential XSS or malformed DOM")
		}
		if !strings.Contains(htmlContent, "Accessibility First Corp &amp; Partners &lt;Test&gt;") {
			t.Errorf("expected HTML-escaped organization name, got HTML:\n%s", htmlContent)
		}
	})
}
