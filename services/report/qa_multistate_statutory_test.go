package report

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/airomhq/airom/services/compliancedb"
)

// TestQA_StatutoryCompleteness_BIPA_TRAIGA_VCDPA comprehensively audits generated
// compliance reports against exact statutory citations and mandatory legal disclosures:
// 1. Illinois BIPA: 740 ILCS 14/10, 14/15(a), 14/15(b)-(c), 14/15(e)
// 2. Texas TRAIGA: Tex. Gov't Code § 2054.601, § 2054.602-603, § 2054.604 (HB 2060)
// 3. Virginia VCDPA: Va. Code § 59.1-575, § 59.1-577-578, § 59.1-580(A)(3)
func TestQA_StatutoryCompleteness_BIPA_TRAIGA_VCDPA(t *testing.T) {
	// =========================================================================
	// 1. ILLINOIS BIPA STATUTORY COMPLETENESS AUDIT (740 ILCS 14/)
	// =========================================================================
	t.Run("BIPA_740_ILCS_14_StatutoryAudit", func(t *testing.T) {
		bipaEvidence := map[EvidenceKey]EvidenceRef{
			"src/biometrics/facial_detector.py:42": {
				AIBOMID:     "aibom-il-face-01",
				FilePath:    "src/biometrics/facial_detector.py",
				LineNumber:  42,
				ComponentID: "comp-bipa-face-embed",
				ModelName:   "facenet-embeddings-v2",
				Kind:        "biometric-model",
				Confidence:  0.99,
			},
			"src/voice/speaker_verification.py:88": {
				AIBOMID:     "aibom-il-voice-02",
				FilePath:    "src/voice/speaker_verification.py",
				LineNumber:  88,
				ComponentID: "comp-bipa-voiceprint",
				ModelName:   "ecapa-tdnn-voiceprint",
				Kind:        "biometric-model",
				Confidence:  0.98,
			},
		}

		bipaData := &BIPAData{
			RetentionScheduleDoc: "POL-BIO-RETENTION-2026-V3",
			BiometricDataTypes:   []string{"Facial Geometry Vectors", "Acoustic Speaker Voiceprints", "Retina/Iris Geometry"},
			WrittenConsentCount:  25000,
			StorageEncryption:    "AES-256-GCM at rest / TLS 1.3 in transit with FIPS 140-3 HSM",
		}

		bipaReq := ReportRequest{
			OrgID:         "org-il-biosecure",
			OrgName:       "BioSecure Technologies Illinois Corp",
			RepoID:        "repo-biometric-access",
			RepoName:      "facial-voice-auth-pipeline",
			CommitSHA:     "sha256-bipa-740ilcs-c0ffee",
			Framework:     "illinois-bipa",
			EvidenceIndex: bipaEvidence,
			SignerName:    "Sarah Jenkins, Esq.",
			SignerTitle:   "Chief Privacy Officer & General Counsel",
		}

		report, err := GenerateBIPAReport(bipaReq, bipaData)
		if err != nil {
			t.Fatalf("GenerateBIPAReport failed: %v", err)
		}

		// Top-level Metadata Audit
		if report.Framework != "illinois-bipa" {
			t.Errorf("expected framework 'illinois-bipa', got '%s'", report.Framework)
		}
		if report.OrgName != bipaReq.OrgName {
			t.Errorf("expected OrgName '%s', got '%s'", bipaReq.OrgName, report.OrgName)
		}
		if report.RepoName != bipaReq.RepoName {
			t.Errorf("expected RepoName '%s', got '%s'", bipaReq.RepoName, report.RepoName)
		}
		if report.CommitSHA != bipaReq.CommitSHA {
			t.Errorf("expected CommitSHA '%s', got '%s'", bipaReq.CommitSHA, report.CommitSHA)
		}
		if report.SignerName != bipaReq.SignerName {
			t.Errorf("expected SignerName '%s', got '%s'", bipaReq.SignerName, report.SignerName)
		}
		if report.SignerTitle != bipaReq.SignerTitle {
			t.Errorf("expected SignerTitle '%s', got '%s'", bipaReq.SignerTitle, report.SignerTitle)
		}
		if !report.AllCitationsValid {
			t.Errorf("expected AllCitationsValid=true for grounded BIPA report")
		}
		if report.Metadata["statute"] != "Illinois BIPA (740 ILCS 14/)" {
			t.Errorf("expected metadata statute 'Illinois BIPA (740 ILCS 14/)', got '%s'", report.Metadata["statute"])
		}
		if report.Metadata["jurisdiction"] != "State of Illinois, USA" {
			t.Errorf("expected jurisdiction 'State of Illinois, USA', got '%s'", report.Metadata["jurisdiction"])
		}

		// Verify Mandatory 4 Sections
		if len(report.Sections) != 4 {
			t.Fatalf("expected exactly 4 BIPA sections, got %d", len(report.Sections))
		}

		// Section 1: 740 ILCS 14/10 Biometric Identification & Scope
		sec1 := report.Sections[0]
		if sec1.ID != "sec-01-biometric-overview" {
			t.Errorf("sec1: expected ID 'sec-01-biometric-overview', got '%s'", sec1.ID)
		}
		if sec1.StatuteRef != "740 ILCS 14/10" {
			t.Errorf("sec1: expected StatuteRef '740 ILCS 14/10', got '%s'", sec1.StatuteRef)
		}
		if !strings.Contains(sec1.Title, "Biometric AI Pipeline Identification") {
			t.Errorf("sec1: title '%s' missing Biometric AI Pipeline Identification keyword", sec1.Title)
		}
		if !strings.Contains(sec1.Prose, "740 ILCS 14/10") {
			t.Errorf("sec1: prose missing citation to 740 ILCS 14/10")
		}
		if len(sec1.Citations) == 0 {
			t.Errorf("sec1: expected grounded citations, got 0")
		}

		// Section 2: 740 ILCS 14/15(a) Written Retention Schedule & Destruction Policy
		sec2 := report.Sections[1]
		if sec2.ID != "sec-02-retention-policy" {
			t.Errorf("sec2: expected ID 'sec-02-retention-policy', got '%s'", sec2.ID)
		}
		if sec2.StatuteRef != "740 ILCS 14/15(a)" {
			t.Errorf("sec2: expected StatuteRef '740 ILCS 14/15(a)', got '%s'", sec2.StatuteRef)
		}
		if !strings.Contains(sec2.Title, "Written Retention Schedule & Destruction Policy") {
			t.Errorf("sec2: title '%s' missing retention keyword", sec2.Title)
		}
		if !strings.Contains(sec2.Prose, "740 ILCS 14/15(a)") {
			t.Errorf("sec2: prose missing 740 ILCS 14/15(a) citation")
		}
		if !strings.Contains(sec2.Prose, "POL-BIO-RETENTION-2026-V3") {
			t.Errorf("sec2: prose missing retention schedule document identifier")
		}
		if !strings.Contains(sec2.Prose, "3 years") {
			t.Errorf("sec2: prose missing statutory 3-year destruction standard")
		}
		if !strings.Contains(sec2.Prose, "AES-256-GCM") {
			t.Errorf("sec2: prose missing storage security/encryption disclosure")
		}

		// Section 3: 740 ILCS 14/15(b)-(c) Prior Informed Consent & Profit Bar
		sec3 := report.Sections[2]
		if sec3.ID != "sec-03-informed-consent" {
			t.Errorf("sec3: expected ID 'sec-03-informed-consent', got '%s'", sec3.ID)
		}
		if sec3.StatuteRef != "740 ILCS 14/15(b)-(c)" {
			t.Errorf("sec3: expected StatuteRef '740 ILCS 14/15(b)-(c)', got '%s'", sec3.StatuteRef)
		}
		if !strings.Contains(sec3.Title, "Prior Written Informed Consent & Profit Bar") {
			t.Errorf("sec3: title '%s' missing consent & profit bar keyword", sec3.Title)
		}
		if !strings.Contains(sec3.Prose, "740 ILCS 14/15(b)-(c)") {
			t.Errorf("sec3: prose missing 740 ILCS 14/15(b)-(c) citation")
		}
		if !strings.Contains(sec3.Prose, "Facial Geometry Vectors") || !strings.Contains(sec3.Prose, "Acoustic Speaker Voiceprints") {
			t.Errorf("sec3: prose missing biometric modality disclosures")
		}
		if !strings.Contains(sec3.Prose, "25000 subjects") {
			t.Errorf("sec3: prose missing written releases count")
		}
		if !strings.Contains(sec3.Prose, "selling, leasing, or trading") {
			t.Errorf("sec3: prose missing commercial profit prohibition language")
		}

		// Section 4: 740 ILCS 14/15(e) Executive Privacy Attestation
		sec4 := report.Sections[3]
		if sec4.ID != "sec-04-attestation" {
			t.Errorf("sec4: expected ID 'sec-04-attestation', got '%s'", sec4.ID)
		}
		if sec4.StatuteRef != "740 ILCS 14/15(e)" {
			t.Errorf("sec4: expected StatuteRef '740 ILCS 14/15(e)', got '%s'", sec4.StatuteRef)
		}
		if !strings.Contains(sec4.Title, "Executive Privacy Attestation") {
			t.Errorf("sec4: title '%s' missing attestation keyword", sec4.Title)
		}
		if !strings.Contains(sec4.Prose, "Sarah Jenkins, Esq.") {
			t.Errorf("sec4: prose missing signer name")
		}
		if !strings.Contains(sec4.Prose, "Chief Privacy Officer & General Counsel") {
			t.Errorf("sec4: prose missing signer title")
		}
		if !strings.Contains(sec4.Prose, "/s/ Sarah Jenkins, Esq.") {
			t.Errorf("sec4: prose missing valid digital signature block '/s/'")
		}
		if !strings.Contains(sec4.Prose, bipaReq.OrgName) || !strings.Contains(sec4.Prose, bipaReq.CommitSHA) {
			t.Errorf("sec4: prose missing deployer org or commit SHA")
		}

		// Test BIPA Defaults
		defaultRep, err := GenerateBIPAReport(ReportRequest{RepoID: "default-bipa"}, nil)
		if err != nil {
			t.Fatalf("failed to generate default BIPA report: %v", err)
		}
		if defaultRep.SignerName != "Chief Privacy Officer" {
			t.Errorf("expected default signer 'Chief Privacy Officer', got '%s'", defaultRep.SignerName)
		}
		if defaultRep.SignerTitle != "Authorized Compliance Signer" {
			t.Errorf("expected default title 'Authorized Compliance Signer', got '%s'", defaultRep.SignerTitle)
		}
	})

	// =========================================================================
	// 2. TEXAS TRAIGA STATUTORY COMPLETENESS AUDIT (Tex. Gov't Code § 2054.601-604)
	// =========================================================================
	t.Run("TRAIGA_Tex_Gov_Code_2054_StatutoryAudit", func(t *testing.T) {
		txEvidence := map[EvidenceKey]EvidenceRef{
			"src/gov/benefits_decision.py:55": {
				AIBOMID:     "aibom-tx-gov-01",
				FilePath:    "src/gov/benefits_decision.py",
				LineNumber:  55,
				ComponentID: "comp-tx-benefits-algo",
				ModelName:   "texas-benefits-evaluator",
				Kind:        "algorithmic-decision-system",
				Confidence:  0.99,
			},
		}

		txData := &TRAIGAData{
			RegistryID:         "TX-AGY-REG-2026-98765",
			RiskTier:           "Tier 3 (Consequential Impact / High-Risk State Operations)",
			HumanOversightRole: "State Agency Human-in-the-Loop Appeals Supervisor",
			WatermarkMethod:    "C2PA Cryptographic Provenance Manifest + ISO 12641 Steganographic Tag",
		}

		txReq := ReportRequest{
			OrgID:         "org-tx-health",
			OrgName:       "Texas Health & Human Services Agency",
			RepoID:        "repo-tx-benefits",
			RepoName:      "automated-benefits-determinations",
			CommitSHA:     "sha256-tx-traiga-hb2060-feedface",
			Framework:     "texas-traiga",
			EvidenceIndex: txEvidence,
			SignerName:    "Marcus Vance",
			SignerTitle:   "Designated State AI Ethics Officer",
		}

		report, err := GenerateTRAIGAReport(txReq, txData)
		if err != nil {
			t.Fatalf("GenerateTRAIGAReport failed: %v", err)
		}

		// Top-level Metadata Audit
		if report.Framework != "texas-traiga" {
			t.Errorf("expected framework 'texas-traiga', got '%s'", report.Framework)
		}
		if report.OrgName != txReq.OrgName {
			t.Errorf("expected OrgName '%s', got '%s'", txReq.OrgName, report.OrgName)
		}
		if report.RepoName != txReq.RepoName {
			t.Errorf("expected RepoName '%s', got '%s'", txReq.RepoName, report.RepoName)
		}
		if report.CommitSHA != txReq.CommitSHA {
			t.Errorf("expected CommitSHA '%s', got '%s'", txReq.CommitSHA, report.CommitSHA)
		}
		if report.SignerName != txReq.SignerName {
			t.Errorf("expected SignerName '%s', got '%s'", txReq.SignerName, report.SignerName)
		}
		if report.SignerTitle != txReq.SignerTitle {
			t.Errorf("expected SignerTitle '%s', got '%s'", txReq.SignerTitle, report.SignerTitle)
		}
		if !report.AllCitationsValid {
			t.Errorf("expected AllCitationsValid=true for grounded TRAIGA report")
		}
		if report.Metadata["statute"] != "Texas TRAIGA (HB 2060)" {
			t.Errorf("expected metadata statute 'Texas TRAIGA (HB 2060)', got '%s'", report.Metadata["statute"])
		}
		if report.Metadata["jurisdiction"] != "State of Texas, USA" {
			t.Errorf("expected jurisdiction 'State of Texas, USA', got '%s'", report.Metadata["jurisdiction"])
		}

		// Verify Mandatory 3 Sections
		if len(report.Sections) != 3 {
			t.Fatalf("expected exactly 3 TRAIGA sections, got %d", len(report.Sections))
		}

		// Section 1: Tex. Gov't Code § 2054.601 Texas Algorithmic System Inventory & Registry
		sec1 := report.Sections[0]
		if sec1.ID != "sec-01-registry-overview" {
			t.Errorf("sec1: expected ID 'sec-01-registry-overview', got '%s'", sec1.ID)
		}
		if sec1.StatuteRef != "Tex. Gov't Code § 2054.601" {
			t.Errorf("sec1: expected StatuteRef 'Tex. Gov't Code § 2054.601', got '%s'", sec1.StatuteRef)
		}
		if !strings.Contains(sec1.Title, "Texas Algorithmic System Inventory & Registry") {
			t.Errorf("sec1: title '%s' missing registry keyword", sec1.Title)
		}
		if !strings.Contains(sec1.Prose, "TX-AGY-REG-2026-98765") {
			t.Errorf("sec1: prose missing Texas Registry ID")
		}
		if len(sec1.Citations) == 0 {
			t.Errorf("sec1: expected grounded citations, got 0")
		}

		// Section 2: Tex. Gov't Code § 2054.602-603 Algorithmic Risk Classification & Human Oversight
		sec2 := report.Sections[1]
		if sec2.ID != "sec-02-risk-oversight" {
			t.Errorf("sec2: expected ID 'sec-02-risk-oversight', got '%s'", sec2.ID)
		}
		if sec2.StatuteRef != "Tex. Gov't Code § 2054.602" {
			t.Errorf("sec2: expected StatuteRef 'Tex. Gov't Code § 2054.602', got '%s'", sec2.StatuteRef)
		}
		if !strings.Contains(sec2.Title, "Algorithmic Risk Classification & Human Oversight") {
			t.Errorf("sec2: title '%s' missing risk/oversight keyword", sec2.Title)
		}
		if !strings.Contains(sec2.Prose, "Tex. Gov't Code § 2054.602-603") {
			t.Errorf("sec2: prose missing statutory citation 'Tex. Gov't Code § 2054.602-603'")
		}
		if !strings.Contains(sec2.Prose, "Tier 3") {
			t.Errorf("sec2: prose missing risk classification tier")
		}
		if !strings.Contains(sec2.Prose, "State Agency Human-in-the-Loop Appeals Supervisor") {
			t.Errorf("sec2: prose missing human oversight role")
		}
		if !strings.Contains(sec2.Prose, "C2PA Cryptographic Provenance Manifest") {
			t.Errorf("sec2: prose missing synthetic media watermark disclosure")
		}

		// Section 3: Tex. Gov't Code § 2054.604 Authorized Texas Governance Attestation
		sec3 := report.Sections[2]
		if sec3.ID != "sec-03-attestation" {
			t.Errorf("sec3: expected ID 'sec-03-attestation', got '%s'", sec3.ID)
		}
		if sec3.StatuteRef != "Tex. Gov't Code § 2054.604" {
			t.Errorf("sec3: expected StatuteRef 'Tex. Gov't Code § 2054.604', got '%s'", sec3.StatuteRef)
		}
		if !strings.Contains(sec3.Title, "Authorized Texas Governance Attestation") {
			t.Errorf("sec3: title '%s' missing attestation keyword", sec3.Title)
		}
		if !strings.Contains(sec3.Prose, "Marcus Vance") {
			t.Errorf("sec3: prose missing signer name")
		}
		if !strings.Contains(sec3.Prose, "Designated State AI Ethics Officer") {
			t.Errorf("sec3: prose missing signer title")
		}
		if !strings.Contains(sec3.Prose, "/s/ Marcus Vance") {
			t.Errorf("sec3: prose missing digital signature '/s/'")
		}
		if !strings.Contains(sec3.Prose, "TX-AGY-REG-2026-98765") {
			t.Errorf("sec3: prose missing registry ID in signature block")
		}

		// Test TRAIGA Defaults
		defaultRep, err := GenerateTRAIGAReport(ReportRequest{RepoID: "default-tx"}, nil)
		if err != nil {
			t.Fatalf("failed to generate default TRAIGA report: %v", err)
		}
		if defaultRep.SignerName != "Designated AI Officer" {
			t.Errorf("expected default signer 'Designated AI Officer', got '%s'", defaultRep.SignerName)
		}
		if defaultRep.SignerTitle != "Authorized Representative" {
			t.Errorf("expected default title 'Authorized Representative', got '%s'", defaultRep.SignerTitle)
		}
	})

	// =========================================================================
	// 3. VIRGINIA VCDPA STATUTORY COMPLETENESS AUDIT (Va. Code § 59.1-575-580)
	// =========================================================================
	t.Run("VCDPA_Va_Code_59_1_StatutoryAudit", func(t *testing.T) {
		vaEvidence := map[EvidenceKey]EvidenceRef{
			"src/profiling/consumer_risk.py:64": {
				AIBOMID:     "aibom-va-profile-01",
				FilePath:    "src/profiling/consumer_risk.py",
				LineNumber:  64,
				ComponentID: "comp-va-risk-scorer",
				ModelName:   "vcdpa-consumer-risk-scorer",
				Kind:        "profiling-decision-system",
				Confidence:  0.98,
			},
		}

		vaData := &VCDPAData{
			AssessmentID:    "DPA-VA-2026-FIN-44001",
			ProfilingTypes:  []string{"Targeted Financial Risk Scoring", "Consumer Behavior Segmentation", "Automated Eligibility Scoring"},
			OptOutMechanism: "Consumer Privacy Rights Webhook & Toll-Free Interactive Agent",
			DataMinimized:   true,
		}

		vaReq := ReportRequest{
			OrgID:         "org-va-dominion",
			OrgName:       "Old Dominion Financial Technologies Inc.",
			RepoID:        "repo-va-risk",
			RepoName:      "consumer-scoring-service",
			CommitSHA:     "sha256-va-vcdpa-591575-decafbad",
			Framework:     "virginia-vcdpa",
			EvidenceIndex: vaEvidence,
			SignerName:    "Harrison Brooks",
			SignerTitle:   "Chief Privacy Officer & Data Protection Officer",
		}

		report, err := GenerateVCDPAReport(vaReq, vaData)
		if err != nil {
			t.Fatalf("GenerateVCDPAReport failed: %v", err)
		}

		// Top-level Metadata Audit
		if report.Framework != "virginia-vcdpa" {
			t.Errorf("expected framework 'virginia-vcdpa', got '%s'", report.Framework)
		}
		if report.OrgName != vaReq.OrgName {
			t.Errorf("expected OrgName '%s', got '%s'", vaReq.OrgName, report.OrgName)
		}
		if report.RepoName != vaReq.RepoName {
			t.Errorf("expected RepoName '%s', got '%s'", vaReq.RepoName, report.RepoName)
		}
		if report.CommitSHA != vaReq.CommitSHA {
			t.Errorf("expected CommitSHA '%s', got '%s'", vaReq.CommitSHA, report.CommitSHA)
		}
		if report.SignerName != vaReq.SignerName {
			t.Errorf("expected SignerName '%s', got '%s'", vaReq.SignerName, report.SignerName)
		}
		if report.SignerTitle != vaReq.SignerTitle {
			t.Errorf("expected SignerTitle '%s', got '%s'", vaReq.SignerTitle, report.SignerTitle)
		}
		if !report.AllCitationsValid {
			t.Errorf("expected AllCitationsValid=true for grounded VCDPA report")
		}
		if report.Metadata["statute"] != "Virginia VCDPA (Va. Code § 59.1-575)" {
			t.Errorf("expected metadata statute 'Virginia VCDPA (Va. Code § 59.1-575)', got '%s'", report.Metadata["statute"])
		}
		if report.Metadata["jurisdiction"] != "Commonwealth of Virginia, USA" {
			t.Errorf("expected jurisdiction 'Commonwealth of Virginia, USA', got '%s'", report.Metadata["jurisdiction"])
		}

		// Verify Mandatory 3 Sections
		if len(report.Sections) != 3 {
			t.Fatalf("expected exactly 3 VCDPA sections, got %d", len(report.Sections))
		}

		// Section 1: Va. Code § 59.1-580(A)(3) Automated Profiling System & DPA Identification
		sec1 := report.Sections[0]
		if sec1.ID != "sec-01-profiling-overview" {
			t.Errorf("sec1: expected ID 'sec-01-profiling-overview', got '%s'", sec1.ID)
		}
		if sec1.StatuteRef != "Va. Code § 59.1-580(A)(3)" {
			t.Errorf("sec1: expected StatuteRef 'Va. Code § 59.1-580(A)(3)', got '%s'", sec1.StatuteRef)
		}
		if !strings.Contains(sec1.Title, "Automated Profiling System & DPA Identification") {
			t.Errorf("sec1: title '%s' missing profiling/DPA keyword", sec1.Title)
		}
		if !strings.Contains(sec1.Prose, "Va. Code § 59.1-580") {
			t.Errorf("sec1: prose missing Va. Code § 59.1-580 citation")
		}
		if !strings.Contains(sec1.Prose, "DPA-VA-2026-FIN-44001") {
			t.Errorf("sec1: prose missing Assessment ID")
		}
		if len(sec1.Citations) == 0 {
			t.Errorf("sec1: expected grounded citations, got 0")
		}

		// Section 2: Va. Code § 59.1-577-578 Consumer Opt-Out & Purpose Limitation Safeguards
		sec2 := report.Sections[1]
		if sec2.ID != "sec-02-optout-minimization" {
			t.Errorf("sec2: expected ID 'sec-02-optout-minimization', got '%s'", sec2.ID)
		}
		if sec2.StatuteRef != "Va. Code § 59.1-577" {
			t.Errorf("sec2: expected StatuteRef 'Va. Code § 59.1-577', got '%s'", sec2.StatuteRef)
		}
		if !strings.Contains(sec2.Title, "Consumer Opt-Out & Purpose Limitation Safeguards") {
			t.Errorf("sec2: title '%s' missing opt-out keyword", sec2.Title)
		}
		if !strings.Contains(sec2.Prose, "Va. Code § 59.1-577-578") {
			t.Errorf("sec2: prose missing Va. Code § 59.1-577-578 citation")
		}
		if !strings.Contains(sec2.Prose, "Targeted Financial Risk Scoring") {
			t.Errorf("sec2: prose missing profiling modalities")
		}
		if !strings.Contains(sec2.Prose, "Consumer Privacy Rights Webhook & Toll-Free Interactive Agent") {
			t.Errorf("sec2: prose missing consumer opt-out mechanism")
		}
		if !strings.Contains(sec2.Prose, "Data Minimization Verified") || !strings.Contains(sec2.Prose, "true") {
			t.Errorf("sec2: prose missing data minimization verification")
		}

		// Section 3: Va. Code § 59.1-580 Data Protection Assessment Attestation
		sec3 := report.Sections[2]
		if sec3.ID != "sec-03-attestation" {
			t.Errorf("sec3: expected ID 'sec-03-attestation', got '%s'", sec3.ID)
		}
		if sec3.StatuteRef != "Va. Code § 59.1-580" {
			t.Errorf("sec3: expected StatuteRef 'Va. Code § 59.1-580', got '%s'", sec3.StatuteRef)
		}
		if !strings.Contains(sec3.Title, "Data Protection Assessment Attestation") {
			t.Errorf("sec3: title '%s' missing DPA attestation keyword", sec3.Title)
		}
		if !strings.Contains(sec3.Prose, "Harrison Brooks") {
			t.Errorf("sec3: prose missing signer name")
		}
		if !strings.Contains(sec3.Prose, "Chief Privacy Officer & Data Protection Officer") {
			t.Errorf("sec3: prose missing signer title")
		}
		if !strings.Contains(sec3.Prose, "/s/ Harrison Brooks") {
			t.Errorf("sec3: prose missing digital signature '/s/'")
		}
		if !strings.Contains(sec3.Prose, "DPA-VA-2026-FIN-44001") {
			t.Errorf("sec3: prose missing assessment ID in signature block")
		}

		// Test VCDPA Defaults
		defaultRep, err := GenerateVCDPAReport(ReportRequest{RepoID: "default-va"}, nil)
		if err != nil {
			t.Fatalf("failed to generate default VCDPA report: %v", err)
		}
		if defaultRep.SignerName != "Chief Privacy Officer" {
			t.Errorf("expected default signer 'Chief Privacy Officer', got '%s'", defaultRep.SignerName)
		}
		if defaultRep.SignerTitle != "Authorized Controller Signer" {
			t.Errorf("expected default title 'Authorized Controller Signer', got '%s'", defaultRep.SignerTitle)
		}
	})
}

// TestQA_AdversarialStateCitationTampering verifies that forged evidence tags,
// fabricated file paths, hallucinated line numbers, and uncited factual assertions
// across BIPA, TRAIGA, and VCDPA prose are detected with 100% precision.
func TestQA_AdversarialStateCitationTampering(t *testing.T) {
	// Baseline authentic multi-state evidence index
	groundTruthEvidence := map[EvidenceKey]EvidenceRef{
		"src/bio/face_embed.py:33": {
			AIBOMID:     "aibom-auth-bipa-01",
			FilePath:    "src/bio/face_embed.py",
			LineNumber:  33,
			ComponentID: "comp-bipa-face",
			ModelName:   "facenet-embeddings",
			Kind:        "biometric-model",
			Confidence:  0.99,
		},
		"src/tx/scoring_registry.py:44": {
			AIBOMID:     "aibom-auth-tx-01",
			FilePath:    "src/tx/scoring_registry.py",
			LineNumber:  44,
			ComponentID: "comp-tx-reg",
			ModelName:   "tx-gov-evaluator",
			Kind:        "decision-engine",
			Confidence:  0.98,
		},
		"src/va/dpa_classifier.py:55": {
			AIBOMID:     "aibom-auth-va-01",
			FilePath:    "src/va/dpa_classifier.py",
			LineNumber:  55,
			ComponentID: "comp-va-dpa",
			ModelName:   "va-consumer-classifier",
			Kind:        "profiling-model",
			Confidence:  0.97,
		},
	}

	// -------------------------------------------------------------------------
	// 1. Illinois BIPA Adversarial Tampering Tests
	// -------------------------------------------------------------------------
	t.Run("BIPA_AdversarialTampering", func(t *testing.T) {
		// Injection A: Fabricated path and forged AIBOM ID
		forgedBIPAProse := "Biometric facial scanning deploys unverified neural network at src/nonexistent/fake_retina.py:99 [ev:forged_bipa_tag:src/nonexistent/fake_retina.py:99]."
		resA := ValidateReportCitations(forgedBIPAProse, groundTruthEvidence)

		if resA.InvalidCount != 1 || resA.ValidCount != 0 {
			t.Fatalf("BIPA Injection A: expected 1 invalid, 0 valid; got invalid=%d, valid=%d", resA.InvalidCount, resA.ValidCount)
		}
		if resA.AttestationStatus != StatusInvalidCitationRemoved {
			t.Errorf("BIPA Injection A: expected status %s, got %s", StatusInvalidCitationRemoved, resA.AttestationStatus)
		}
		if !strings.Contains(resA.CleanedProse, "> [INVALID CITATION REMOVED]") {
			t.Errorf("BIPA Injection A: cleaned prose must contain '> [INVALID CITATION REMOVED]', got: %s", resA.CleanedProse)
		}
		if strings.Contains(resA.CleanedProse, "forged_bipa_tag") {
			t.Errorf("BIPA Injection A: forged AIBOM tag must be purged from cleaned prose: %s", resA.CleanedProse)
		}

		// Injection B: Hallucinated line number on real file
		wrongLineBIPAProse := "Face geometry extractor utilizes weights at src/bio/face_embed.py:9999 [ev:aibom-auth-bipa-01:src/bio/face_embed.py:9999]."
		resB := ValidateReportCitations(wrongLineBIPAProse, groundTruthEvidence)

		if resB.InvalidCount != 1 || resB.ValidCount != 0 {
			t.Fatalf("BIPA Injection B: expected 1 invalid for wrong line; got invalid=%d, valid=%d", resB.InvalidCount, resB.ValidCount)
		}
		if !strings.Contains(resB.CleanedProse, "> [INVALID CITATION REMOVED]") {
			t.Errorf("BIPA Injection B: expected invalid marker for line mismatch, got: %s", resB.CleanedProse)
		}

		// Injection C: Uncited factual deployment assertions
		uncitedBIPAClaims := []string{
			"The deployer utilizes high-risk algorithmic scoring for biometric facial identification.",
			"System deploys gemini-2.5-pro for automated retina verification without prior notice.",
			"The inference engine executes model weights across edge camera endpoints.",
		}
		for _, claim := range uncitedBIPAClaims {
			resC := ValidateReportCitations(claim, groundTruthEvidence)
			if resC.UncitedClaims != 1 {
				t.Errorf("BIPA Injection C: claim '%s' should be detected as uncited claim, got %d", claim, resC.UncitedClaims)
			}
			if resC.AttestationStatus != StatusRequiresAttestation {
				t.Errorf("BIPA Injection C: expected %s, got %s", StatusRequiresAttestation, resC.AttestationStatus)
			}
			if !strings.Contains(resC.CleanedProse, "> [MANUAL ATTESTATION REQUIRED]") {
				t.Errorf("BIPA Injection C: expected manual attestation marker for claim '%s', got: %s", claim, resC.CleanedProse)
			}
		}

		// Injection D: Mixed valid, forged, line-mismatched, and uncited claims in BIPA report
		mixedBIPAProse := strings.Join([]string{
			"Evaluation of biometric system under 740 ILCS 14/10.",
			"Authentic facial recognition deploys facenet at src/bio/face_embed.py:33 [ev:aibom-auth-bipa-01:src/bio/face_embed.py:33].",
			"Hallucinated iris scan deploys model at src/fake/iris.py:100 [ev:forged_iris_99:src/fake/iris.py:100].",
			"System utilizes gpt-4o for automated biometric matching across cloud infrastructure.",
		}, "\n")

		resD := ValidateReportCitations(mixedBIPAProse, groundTruthEvidence)
		if resD.ValidCount != 1 || resD.InvalidCount != 1 || resD.UncitedClaims != 1 {
			t.Errorf("BIPA Injection D: expected 1 valid, 1 invalid, 1 uncited; got valid=%d, invalid=%d, uncited=%d",
				resD.ValidCount, resD.InvalidCount, resD.UncitedClaims)
		}
		if resD.AttestationStatus != StatusInvalidCitationRemoved {
			t.Errorf("BIPA Injection D: expected %s, got %s", StatusInvalidCitationRemoved, resD.AttestationStatus)
		}
	})

	// -------------------------------------------------------------------------
	// 2. Texas TRAIGA Adversarial Tampering Tests
	// -------------------------------------------------------------------------
	t.Run("TRAIGA_AdversarialTampering", func(t *testing.T) {
		// Injection A: Fabricated path and forged AIBOM ID
		forgedTXProse := "State registry pipeline deploys automated scoring engine at src/fake_tx/benefits_algo.py:77 [ev:forged_tx_007:src/fake_tx/benefits_algo.py:77]."
		resA := ValidateReportCitations(forgedTXProse, groundTruthEvidence)

		if resA.InvalidCount != 1 || resA.ValidCount != 0 {
			t.Fatalf("TRAIGA Injection A: expected 1 invalid, 0 valid; got invalid=%d, valid=%d", resA.InvalidCount, resA.ValidCount)
		}
		if resA.AttestationStatus != StatusInvalidCitationRemoved {
			t.Errorf("TRAIGA Injection A: expected status %s, got %s", StatusInvalidCitationRemoved, resA.AttestationStatus)
		}
		if !strings.Contains(resA.CleanedProse, "> [INVALID CITATION REMOVED]") {
			t.Errorf("TRAIGA Injection A: cleaned prose missing invalid citation callout: %s", resA.CleanedProse)
		}
		if strings.Contains(resA.CleanedProse, "forged_tx_007") {
			t.Errorf("TRAIGA Injection A: forged AIBOM tag must be removed: %s", resA.CleanedProse)
		}

		// Injection B: Hallucinated line number on authentic Texas file
		wrongLineTXProse := "Decision system utilizes rules at src/tx/scoring_registry.py:12345 [ev:aibom-auth-tx-01:src/tx/scoring_registry.py:12345]."
		resB := ValidateReportCitations(wrongLineTXProse, groundTruthEvidence)

		if resB.InvalidCount != 1 || resB.ValidCount != 0 {
			t.Fatalf("TRAIGA Injection B: expected 1 invalid; got invalid=%d, valid=%d", resB.InvalidCount, resB.ValidCount)
		}
		if !strings.Contains(resB.CleanedProse, "> [INVALID CITATION REMOVED]") {
			t.Errorf("TRAIGA Injection B: expected invalid marker for line mismatch: %s", resB.CleanedProse)
		}

		// Injection C: Uncited factual claims
		uncitedTXClaims := []string{
			"The agency deploys an algorithmic decision system for child welfare determinations.",
			"System utilizes claude-3.7-sonnet for automated Texas regulatory compliance review.",
			"State operator executes automated inference across public assistance registries.",
		}
		for _, claim := range uncitedTXClaims {
			resC := ValidateReportCitations(claim, groundTruthEvidence)
			if resC.UncitedClaims != 1 {
				t.Errorf("TRAIGA Injection C: claim '%s' should be detected as uncited claim, got %d", claim, resC.UncitedClaims)
			}
			if !strings.Contains(resC.CleanedProse, "> [MANUAL ATTESTATION REQUIRED]") {
				t.Errorf("TRAIGA Injection C: expected manual attestation marker: %s", resC.CleanedProse)
			}
		}
	})

	// -------------------------------------------------------------------------
	// 3. Virginia VCDPA Adversarial Tampering Tests
	// -------------------------------------------------------------------------
	t.Run("VCDPA_AdversarialTampering", func(t *testing.T) {
		// Injection A: Fabricated path and forged AIBOM ID
		forgedVAProse := "Data controller deploys high-risk consumer profiling engine at src/fake_va/profiler.py:88 [ev:forged_va_999:src/fake_va/profiler.py:88]."
		resA := ValidateReportCitations(forgedVAProse, groundTruthEvidence)

		if resA.InvalidCount != 1 || resA.ValidCount != 0 {
			t.Fatalf("VCDPA Injection A: expected 1 invalid, 0 valid; got invalid=%d, valid=%d", resA.InvalidCount, resA.ValidCount)
		}
		if resA.AttestationStatus != StatusInvalidCitationRemoved {
			t.Errorf("VCDPA Injection A: expected status %s, got %s", StatusInvalidCitationRemoved, resA.AttestationStatus)
		}
		if !strings.Contains(resA.CleanedProse, "> [INVALID CITATION REMOVED]") {
			t.Errorf("VCDPA Injection A: cleaned prose missing invalid citation callout: %s", resA.CleanedProse)
		}
		if strings.Contains(resA.CleanedProse, "forged_va_999") {
			t.Errorf("VCDPA Injection A: forged AIBOM tag must be removed: %s", resA.CleanedProse)
		}

		// Injection B: Hallucinated line number on authentic Virginia file
		wrongLineVAProse := "DPA assessment utilizes classifier at src/va/dpa_classifier.py:9999 [ev:aibom-auth-va-01:src/va/dpa_classifier.py:9999]."
		resB := ValidateReportCitations(wrongLineVAProse, groundTruthEvidence)

		if resB.InvalidCount != 1 || resB.ValidCount != 0 {
			t.Fatalf("VCDPA Injection B: expected 1 invalid; got invalid=%d, valid=%d", resB.InvalidCount, resB.ValidCount)
		}
		if !strings.Contains(resB.CleanedProse, "> [INVALID CITATION REMOVED]") {
			t.Errorf("VCDPA Injection B: expected invalid marker for line mismatch: %s", resB.CleanedProse)
		}

		// Injection C: Uncited factual claims
		uncitedVAClaims := []string{
			"The scoring engine deploys automated profiling for consumer loan eligibility.",
			"System utilizes mistral-large for behavioral feature extraction and targeting.",
			"The framework configured with model weights without required Data Protection Assessment.",
		}
		for _, claim := range uncitedVAClaims {
			resC := ValidateReportCitations(claim, groundTruthEvidence)
			if resC.UncitedClaims != 1 {
				t.Errorf("VCDPA Injection C: claim '%s' should be detected as uncited claim, got %d", claim, resC.UncitedClaims)
			}
			if !strings.Contains(resC.CleanedProse, "> [MANUAL ATTESTATION REQUIRED]") {
				t.Errorf("VCDPA Injection C: expected manual attestation marker: %s", resC.CleanedProse)
			}
		}

		// Injection D: Multi-claim mixture verification
		mixedVAProse := strings.Join([]string{
			"# Virginia DPA Overview",
			"Controller assesses automated processing under Va. Code § 59.1-580.",
			"Valid consumer profiling deploys classifier at src/va/dpa_classifier.py:55 [ev:aibom-auth-va-01:src/va/dpa_classifier.py:55].",
			"Forged targeted advertising deploys engine at src/fake/ad_engine.py:12 [ev:forged_ad_01:src/fake/ad_engine.py:12].",
			"The application implements llama-3.3-70b for automated consumer credit denials.",
		}, "\n")

		resD := ValidateReportCitations(mixedVAProse, groundTruthEvidence)
		if resD.ValidCount != 1 || resD.InvalidCount != 1 || resD.UncitedClaims != 1 {
			t.Errorf("VCDPA Injection D: expected 1 valid, 1 invalid, 1 uncited; got valid=%d, invalid=%d, uncited=%d",
				resD.ValidCount, resD.InvalidCount, resD.UncitedClaims)
		}
		if resD.AttestationStatus != StatusInvalidCitationRemoved {
			t.Errorf("VCDPA Injection D: expected %s, got %s", StatusInvalidCitationRemoved, resD.AttestationStatus)
		}
	})
}

// TestQA_MultiStateHTMLAccessibility_WCAG audits rendered HTML reports across
// Illinois BIPA, Texas TRAIGA, and Virginia VCDPA for strict WCAG 2.1 AA accessibility compliance:
// 1. Valid DOCTYPE declaration (<!DOCTYPE html>)
// 2. Declared language attribute (<html lang="en">)
// 3. Document metadata (<meta charset="UTF-8">, <meta name="viewport" ...>)
// 4. Semantic landmarks (<header>, <main>, <article>, <section>)
// 5. Heading hierarchy (single <h1> per page, ordered <h2> sections)
// 6. Accessible evidence tables with aria-label, <thead>, <th>, <tbody>
// 7. High-contrast status badges (.badge-verified, .badge-gap)
// 8. Print media stylesheet (@media print)
// 9. Strict HTML entity escaping against XSS injection
func TestQA_MultiStateHTMLAccessibility_WCAG(t *testing.T) {
	stateFrameworkConfigs := []struct {
		Name      string
		Framework string
		GenFunc   func() (*ComplianceReport, error)
	}{
		{
			Name:      "Illinois_BIPA",
			Framework: "illinois-bipa",
			GenFunc: func() (*ComplianceReport, error) {
				evIndex := map[EvidenceKey]EvidenceRef{
					"src/bio/retina.py:77": {
						AIBOMID:     "aibom-il-wcag-01",
						FilePath:    "src/bio/retina.py",
						LineNumber:  77,
						ComponentID: "comp-retina",
						ModelName:   "retinanet-biometric",
						Kind:        "biometric-sensor",
						Confidence:  0.99,
					},
				}
				evals := []compliancedb.ControlEvaluation{
					{
						ID:         "eval-bipa-01",
						ControlID:  "il.bipa.consent",
						StatuteRef: "740 ILCS 14/15(b)",
						Verdict:    compliancedb.VerdictMet,
					},
					{
						ID:         "eval-bipa-02",
						ControlID:  "il.bipa.retention",
						StatuteRef: "740 ILCS 14/15(a)",
						Verdict:    compliancedb.VerdictGap,
						GapMessage: "Missing public retention schedule publication URL.",
					},
				}
				req := ReportRequest{
					OrgName:       "Illinois Biometrics & Security LLC <Dept 4>",
					RepoName:      "bipa-retina-auth",
					CommitSHA:     "sha256-bipa-wcag-test",
					Framework:     "illinois-bipa",
					EvidenceIndex: evIndex,
					Evaluations:   evals,
					SignerName:    "Jane Doe & Co.",
					SignerTitle:   "VP Biometric Compliance",
				}
				return GenerateBIPAReport(req, nil)
			},
		},
		{
			Name:      "Texas_TRAIGA",
			Framework: "texas-traiga",
			GenFunc: func() (*ComplianceReport, error) {
				evIndex := map[EvidenceKey]EvidenceRef{
					"src/tx/engine.py:88": {
						AIBOMID:     "aibom-tx-wcag-01",
						FilePath:    "src/tx/engine.py",
						LineNumber:  88,
						ComponentID: "comp-tx-engine",
						ModelName:   "texas-gov-decision-engine",
						Kind:        "decision-system",
						Confidence:  0.96,
					},
				}
				evals := []compliancedb.ControlEvaluation{
					{
						ID:         "eval-tx-01",
						ControlID:  "tx.traiga.inventory",
						StatuteRef: "Tex. Gov't Code § 2054.601",
						Verdict:    compliancedb.VerdictMet,
					},
				}
				req := ReportRequest{
					OrgName:       "Texas Department of AI Governance <Agency 304>",
					RepoName:      "traiga-benefits-engine",
					CommitSHA:     "sha256-tx-wcag-test",
					Framework:     "texas-traiga",
					EvidenceIndex: evIndex,
					Evaluations:   evals,
					SignerName:    "James Austin & Associates",
					SignerTitle:   "State AI Officer",
				}
				return GenerateTRAIGAReport(req, nil)
			},
		},
		{
			Name:      "Virginia_VCDPA",
			Framework: "virginia-vcdpa",
			GenFunc: func() (*ComplianceReport, error) {
				evIndex := map[EvidenceKey]EvidenceRef{
					"src/va/profiler.py:99": {
						AIBOMID:     "aibom-va-wcag-01",
						FilePath:    "src/va/profiler.py",
						LineNumber:  99,
						ComponentID: "comp-va-profiler",
						ModelName:   "vcdpa-profiling-scorer",
						Kind:        "hosted-model",
						Confidence:  0.95,
					},
				}
				evals := []compliancedb.ControlEvaluation{
					{
						ID:         "eval-va-01",
						ControlID:  "va.vcdpa.dpa",
						StatuteRef: "Va. Code § 59.1-580",
						Verdict:    compliancedb.VerdictMet,
					},
				}
				req := ReportRequest{
					OrgName:       "Commonwealth Data Solutions Inc. <East Region>",
					RepoName:      "vcdpa-profiling-service",
					CommitSHA:     "sha256-va-wcag-test",
					Framework:     "virginia-vcdpa",
					EvidenceIndex: evIndex,
					Evaluations:   evals,
					SignerName:    "Eleanor Fairfax",
					SignerTitle:   "Chief Data Protection Officer",
				}
				return GenerateVCDPAReport(req, nil)
			},
		},
	}

	for _, tc := range stateFrameworkConfigs {
		t.Run(tc.Name, func(t *testing.T) {
			report, err := tc.GenFunc()
			if err != nil {
				t.Fatalf("failed to generate report for %s: %v", tc.Name, err)
			}

			htmlContent := RenderHTML(report)

			// 1. Valid DOCTYPE declaration
			if !strings.HasPrefix(strings.TrimSpace(htmlContent), "<!DOCTYPE html>") {
				t.Errorf("[%s] document must start with '<!DOCTYPE html>'", tc.Name)
			}

			// 2. Declared language attribute
			if !strings.Contains(htmlContent, "<html lang=\"en\">") {
				t.Errorf("[%s] root html element must specify lang attribute '<html lang=\"en\">'", tc.Name)
			}

			// 3. Document meta tags for charset and viewport
			if !strings.Contains(htmlContent, "<meta charset=\"UTF-8\">") {
				t.Errorf("[%s] meta charset UTF-8 missing", tc.Name)
			}
			if !strings.Contains(htmlContent, "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">") {
				t.Errorf("[%s] meta responsive viewport tag missing", tc.Name)
			}

			// 4. Page title present and properly escaped
			titleRegex := regexp.MustCompile(`<title>(.*?)</title>`)
			matches := titleRegex.FindStringSubmatch(htmlContent)
			if len(matches) < 2 || strings.TrimSpace(matches[1]) == "" {
				t.Fatalf("[%s] document must contain non-empty <title> tag", tc.Name)
			}
			if strings.Contains(matches[1], "<") || strings.Contains(matches[1], ">") {
				t.Errorf("[%s] title tag contains unescaped HTML entities: %s", tc.Name, matches[1])
			}

			// 5. Semantic HTML landmarks
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
			for _, lm := range requiredLandmarks {
				if !strings.Contains(htmlContent, lm) {
					t.Errorf("[%s] missing required semantic landmark '%s'", tc.Name, lm)
				}
			}

			// 6. Heading hierarchy: exactly 1 <h1>, multiple <h2>
			h1Regex := regexp.MustCompile(`<h1[^>]*>(.*?)</h1>`)
			h1Matches := h1Regex.FindAllStringSubmatch(htmlContent, -1)
			if len(h1Matches) != 1 {
				t.Errorf("[%s] expected exactly 1 <h1> tag on page, found %d", tc.Name, len(h1Matches))
			}

			h2Regex := regexp.MustCompile(`<h2[^>]*>(.*?)</h2>`)
			h2Matches := h2Regex.FindAllStringSubmatch(htmlContent, -1)
			if len(h2Matches) < len(report.Sections)+1 {
				t.Errorf("[%s] expected at least %d <h2> headings (summary + %d sections), found %d",
					tc.Name, len(report.Sections)+1, len(report.Sections), len(h2Matches))
			}

			// 7. Evidence table accessibility: aria-label, thead, th, tbody
			if !strings.Contains(htmlContent, "<table class=\"evidence-table\" aria-label=\"Evidence Grounding Table\">") {
				t.Errorf("[%s] evidence table missing aria-label=\"Evidence Grounding Table\"", tc.Name)
			}
			if !strings.Contains(htmlContent, "<thead><tr><th>Citation Tag</th><th>Source File</th><th>Line</th><th>Verification Status</th></tr></thead>") {
				t.Errorf("[%s] table missing semantic <thead> with accessible <th> column headers", tc.Name)
			}
			if !strings.Contains(htmlContent, "<tbody>") || !strings.Contains(htmlContent, "</tbody>") {
				t.Errorf("[%s] table missing semantic <tbody> container", tc.Name)
			}

			// 8. High-contrast status badges
			if !strings.Contains(htmlContent, ".badge-verified") || !strings.Contains(htmlContent, ".badge-gap") {
				t.Errorf("[%s] CSS missing .badge-verified or .badge-gap classes", tc.Name)
			}
			if !strings.Contains(htmlContent, "badge-verified") {
				t.Errorf("[%s] table row missing badge-verified rendering", tc.Name)
			}

			// 9. Print media stylesheet
			if !strings.Contains(htmlContent, "@media print") {
				t.Errorf("[%s] missing @media print stylesheet block", tc.Name)
			}

			// 10. Strict HTML escaping / XSS safety
			if strings.Contains(htmlContent, "<Dept 4>") || strings.Contains(htmlContent, "<Agency 304>") || strings.Contains(htmlContent, "<East Region>") {
				t.Errorf("[%s] unescaped angle brackets found in HTML output: potential XSS or malformed DOM", tc.Name)
			}
			if strings.Contains(htmlContent, "& Co.") || strings.Contains(htmlContent, "& Associates") || strings.Contains(htmlContent, "& Security") {
				t.Errorf("[%s] unescaped ampersand found in HTML output", tc.Name)
			}

			// Verify JSON export also works cleanly for the report
			jsonBytes, err := json.Marshal(report)
			if err != nil || len(jsonBytes) == 0 {
				t.Errorf("[%s] JSON marshaling failed: %v", tc.Name, err)
			}

			// Verify Markdown export contains framework title and executive summary
			mdContent := RenderMarkdown(report)
			if !strings.Contains(mdContent, report.Title) || !strings.Contains(mdContent, "Executive Summary") {
				t.Errorf("[%s] Markdown rendering missing title or executive summary", tc.Name)
			}
		})
	}
}
