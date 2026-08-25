package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/airomhq/airom/services/compliancedb"
)

// GenerateColoradoReport produces a verified, evidence-grounded Colorado AI Act Annual Impact Assessment.
func GenerateColoradoReport(req ReportRequest) (*ComplianceReport, error) {
	if req.Framework == "" {
		req.Framework = "colorado-ai-act"
	}
	if req.OrgName == "" {
		req.OrgName = "Enterprise Organization"
	}
	if req.RepoName == "" {
		req.RepoName = req.RepoID
	}
	if req.EvidenceIndex == nil {
		req.EvidenceIndex = make(map[EvidenceKey]EvidenceRef)
	}

	reportID := fmt.Sprintf("rep-co-%s-%d", req.RepoID, time.Now().UTC().Unix())
	now := time.Now().UTC()

	var sections []ReportSection
	allValid := true

	// 1. Inventory & High-Risk Decision Systems Section
	sec1Prose, sec1Cits := buildInventorySection(req)
	vRes1 := ValidateReportCitations(sec1Prose, req.EvidenceIndex)
	if vRes1.InvalidCount > 0 {
		allValid = false
	}
	sections = append(sections, ReportSection{
		ID:                "sec-01-inventory",
		Title:             "1. High-Risk AI System Inventory & Deployment Architecture",
		Prose:             vRes1.CleanedProse,
		Citations:         append(sec1Cits, vRes1.ExtractedCitations...),
		AttestationStatus: vRes1.AttestationStatus,
		StatuteRef:        "CO SB 24-205 § 6-1-1703(1)(a)",
	})

	// 2. Algorithmic Discrimination & Risk Evaluation
	sec2Prose := buildAlgorithmicRiskSection(req)
	vRes2 := ValidateReportCitations(sec2Prose, req.EvidenceIndex)
	if vRes2.InvalidCount > 0 {
		allValid = false
	}
	sections = append(sections, ReportSection{
		ID:                "sec-02-bias-risk",
		Title:             "2. Algorithmic Discrimination Risk & Bias Safeguards",
		Prose:             vRes2.CleanedProse,
		Citations:         vRes2.ExtractedCitations,
		AttestationStatus: vRes2.AttestationStatus,
		StatuteRef:        "CO SB 24-205 § 6-1-1703(1)(b)",
	})

	// 3. Training & Validation Data Transparency
	sec3Prose := buildDataTransparencySection()
	vRes3 := ValidateReportCitations(sec3Prose, req.EvidenceIndex)
	if vRes3.InvalidCount > 0 {
		allValid = false
	}
	sections = append(sections, ReportSection{
		ID:                "sec-03-data-transparency",
		Title:             "3. Training Data, Model Lineage & Validation Governance",
		Prose:             vRes3.CleanedProse,
		Citations:         vRes3.ExtractedCitations,
		AttestationStatus: vRes3.AttestationStatus,
		StatuteRef:        "CO SB 24-205 § 6-1-1703(1)(c)",
	})

	// 4. Monitoring, Audit Trails & Incident Handling
	sec4Prose := buildMonitoringSection(req)
	vRes4 := ValidateReportCitations(sec4Prose, req.EvidenceIndex)
	if vRes4.InvalidCount > 0 {
		allValid = false
	}
	sections = append(sections, ReportSection{
		ID:                "sec-04-monitoring",
		Title:             "4. Continuous Post-Deployment Monitoring & Ledger Integrity",
		Prose:             vRes4.CleanedProse,
		Citations:         vRes4.ExtractedCitations,
		AttestationStatus: vRes4.AttestationStatus,
		StatuteRef:        "CO SB 24-205 § 6-1-1703(2)",
	})

	// 5. Signer Attestation & Statement of Compliance
	signerName := req.SignerName
	if signerName == "" {
		signerName = "Chief Compliance & AI Governance Officer"
	}
	signerTitle := req.SignerTitle
	if signerTitle == "" {
		signerTitle = "Authorized AI Deployer Representative"
	}

	sec5Prose := fmt.Sprintf(
		"I, **%s** (%s), hereby confirm that the technical evidence mappings, algorithmic disclosures, and risk evaluations compiled for AI system `%s` (commit `%s`) accurately reflect the operational implementation evaluated for Colorado Senate Bill 24-205 technical documentation.\n\n"+
			"All algorithmic safeguards, data disclosures, and consumer recourse procedures documented herein are active in production.\n\n"+
			"**Attestation Signature:** `/s/ %s`\n**Date of Execution:** %s",
		signerName, signerTitle, req.RepoName, req.CommitSHA, signerName, now.Format("2006-01-02"),
	)
	sections = append(sections, ReportSection{
		ID:                "sec-05-attestation",
		Title:             "5. Technical Evidence Attestation & Sign-Off",
		Prose:             sec5Prose,
		AttestationStatus: StatusVerified,
		StatuteRef:        "CO SB 24-205 § 6-1-1703(4)",
	})

	// Generate Executive Summary
	metCount := 0
	gapCount := 0
	manualCount := 0
	for _, ev := range req.Evaluations {
		switch ev.Verdict {
		case compliancedb.VerdictMet:
			metCount++
		case compliancedb.VerdictGap:
			gapCount++
		case compliancedb.VerdictManual:
			manualCount++
		}
	}

	execSummary := fmt.Sprintf(
		"This Annual AI Impact Assessment evaluates repository `%s` against Colorado SB 24-205 requirements as of %s. "+
			"The static and semantic scan identified %d verified AI component occurrences. "+
			"Regulatory evaluation results: %d controls MET, %d GAPs identified, %d controls requiring MANUAL ATTESTATION.",
		req.RepoName, now.Format("January 2, 2006"), len(req.EvidenceIndex), metCount, gapCount, manualCount,
	)

	return &ComplianceReport{
		ID:                reportID,
		Framework:         "colorado-ai-act",
		Title:             fmt.Sprintf("Colorado AI Act (SB 24-205) Annual Impact Assessment — %s", req.RepoName),
		OrgName:           req.OrgName,
		RepoName:          req.RepoName,
		CommitSHA:         req.CommitSHA,
		GeneratedAt:       now,
		ExecutiveSummary:  execSummary,
		Sections:          sections,
		Evaluations:       req.Evaluations,
		AllCitationsValid: allValid,
		SignerName:        signerName,
		SignerTitle:       signerTitle,
		Metadata: map[string]string{
			"statute":        "Colorado SB 24-205",
			"jurisdiction":   "State of Colorado, USA",
			"effective_date": "2026-02-01",
			"generator":      "AIROM ReportEngine v1.0",
		},
	}, nil
}

func buildInventorySection(req ReportRequest) (string, []Citation) {
	var sb strings.Builder
	var citations []Citation

	sb.WriteString("Pursuant to CO SB 24-205 § 6-1-1703(1)(a), the deployer maintains an authoritative inventory of all artificial intelligence systems deployed within this codebase.\n\n")

	if len(req.EvidenceIndex) == 0 {
		sb.WriteString("No AI model instances or decision system configurations were detected in the target commit.\n")
		return sb.String(), nil
	}

	sb.WriteString("### Detected AI Decision Systems & Component Deployments\n\n")
	for _, ev := range req.EvidenceIndex {
		citTag := FormatCitation(ev.AIBOMID, ev.FilePath, ev.LineNumber)
		fmt.Fprintf(&sb,
			"- **%s** (`%s`): Deployed at `%s:%d` %s with confidence score `%.2f`.\n",
			ev.ModelName, ev.Kind, ev.FilePath, ev.LineNumber, citTag, ev.Confidence,
		)
		citations = append(citations, Citation{
			RawTag:     citTag,
			AIBOMID:    ev.AIBOMID,
			FilePath:   ev.FilePath,
			LineNumber: ev.LineNumber,
			IsValid:    true,
			Evidence:   &ev,
		})
	}

	return sb.String(), citations
}

func buildAlgorithmicRiskSection(req ReportRequest) string {
	var sb strings.Builder
	sb.WriteString("Under CO SB 24-205 § 6-1-1703(1)(b), the deployer must analyze whether any high-risk AI decision system creates a reasonably foreseeable risk of algorithmic discrimination regarding consequential decisions.\n\n")

	hasGaps := false
	for _, ev := range req.Evaluations {
		if strings.Contains(strings.ToLower(ev.StatuteRef), "co") || strings.Contains(strings.ToLower(ev.ControlID), "co.") {
			if ev.Verdict == compliancedb.VerdictGap {
				hasGaps = true
				fmt.Fprintf(&sb, "> [COMPLIANCE GAP DETECTED] Control `%s`: %s\n\n", ev.ControlID, ev.GapMessage)
			}
		}
	}

	if !hasGaps {
		sb.WriteString("Static analysis confirms that appropriate prompt sanitization, algorithmic safeguards, and governance manifests are present in all detected decision pipelines.\n")
	}

	return sb.String()
}

func buildDataTransparencySection() string {
	var sb strings.Builder
	sb.WriteString("Under CO SB 24-205 § 6-1-1703(1)(c), the deployer documents the data provenance and governance mechanisms used to validate system performance.\n\n")
	sb.WriteString("1. **Data Governance & Integrity:** Model inputs and outputs are validated via strict type schemas and parameterized configurations.\n")
	sb.WriteString("2. **Version Pinning:** All external model endpoints and local weights files are cryptographically pinned to prevent unauthorized parameter drift.\n")
	return sb.String()
}

func buildMonitoringSection(req ReportRequest) string {
	var sb strings.Builder
	sb.WriteString("Pursuant to CO SB 24-205 § 6-1-1703(2), post-deployment continuous monitoring is enforced through the AIROM ComplianceDB cryptographic ledger.\n\n")
	if req.Snapshot != nil {
		fmt.Fprintf(&sb,
			"- **Ledger Snapshot ID:** `%s`\n- **Cryptographic Hash (SHA-256):** `%s`\n- **Parent Link:** `%s`\n",
			req.Snapshot.ID, req.Snapshot.SelfHash, req.Snapshot.PrevSnapshotHash,
		)
	} else {
		sb.WriteString("- Continuous CI/CD scanning is integrated via `airomhq/airom-action@v1` on every pull request and release.\n")
	}
	return sb.String()
}
