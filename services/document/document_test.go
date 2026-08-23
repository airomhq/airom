package document

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/services/compliancedb"
	"github.com/airomhq/airom/services/report"
)

func TestSecurity_GenerateAndVerifyHumanToken_Success(t *testing.T) {
	secret := []byte("super-secret-key-for-test-32bytes")
	req := TokenRequest{
		UserID:     "user-123",
		UserEmail:  "officer@acme.com",
		DocumentID: "doc-co-100",
	}

	tokenStr, tok, err := GenerateHumanToken(secret, req, 90*time.Second)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	verified, err := VerifyHumanToken(secret, tokenStr, "doc-co-100")
	if err != nil {
		t.Fatalf("failed to verify valid token: %v", err)
	}

	if verified.UserID != "user-123" || verified.DocumentID != "doc-co-100" || verified.TokenID != tok.TokenID {
		t.Errorf("token payload mismatch: %+v", verified)
	}
}

func TestSecurity_ExpiredHumanToken_FailsClosed(t *testing.T) {
	secret := []byte("super-secret-key-for-test-32bytes")
	req := TokenRequest{
		UserID:     "user-123",
		DocumentID: "doc-co-100",
	}

	// Generate with 1 millisecond TTL
	tokenStr, _, err := GenerateHumanToken(secret, req, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	time.Sleep(10 * time.Millisecond) // Wait for expiry

	_, err = VerifyHumanToken(secret, tokenStr, "doc-co-100")
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected token expiration error, got: %v", err)
	}
}

func TestSecurity_TamperedHumanToken_FailsClosed(t *testing.T) {
	secret := []byte("super-secret-key-for-test-32bytes")
	req := TokenRequest{
		UserID:     "user-123",
		DocumentID: "doc-co-100",
	}

	tokenStr, _, _ := GenerateHumanToken(secret, req, 90*time.Second)

	// Tamper with signature
	tampered := tokenStr + "tampered"
	_, err := VerifyHumanToken(secret, tampered, "doc-co-100")
	if err == nil || !strings.Contains(err.Error(), "invalid or tampered") {
		t.Errorf("expected signature invalid error, got: %v", err)
	}

	// Tamper with secret
	_, err = VerifyHumanToken([]byte("wrong-secret-key"), tokenStr, "doc-co-100")
	if err == nil || !strings.Contains(err.Error(), "invalid or tampered") {
		t.Errorf("expected wrong secret error, got: %v", err)
	}
}

func TestSecurity_DocumentMismatch_FailsClosed(t *testing.T) {
	secret := []byte("super-secret-key-for-test-32bytes")
	req := TokenRequest{
		UserID:     "user-123",
		DocumentID: "doc-co-100",
	}

	tokenStr, _, _ := GenerateHumanToken(secret, req, 90*time.Second)

	// Attempt to use token on document "doc-co-999"
	_, err := VerifyHumanToken(secret, tokenStr, "doc-co-999")
	if err == nil || !strings.Contains(err.Error(), "not authorized for this document") {
		t.Errorf("expected document mismatch error, got: %v", err)
	}
}

func TestGateway_GreenYellowRedCategorization(t *testing.T) {
	agent := NewAgent([]byte("test-secret-gateway-32bytes-long"))

	req := CreatePackageRequest{
		OrgName:     "Acme Corp",
		RepoID:      "credit-scoring",
		RepoName:    "credit-scoring-pipeline",
		CommitSHA:   "c-100",
		Framework:   "colorado-ai-act",
		AIBOMSHA256: "aibom-sha-xyz",
		EvidenceIndex: map[string]report.EvidenceRef{
			"src/model.py:10": {
				AIBOMID:     "aibom-1",
				FilePath:    "src/model.py",
				LineNumber:  10,
				ComponentID: "comp-1",
				ModelName:   "gpt-4o",
				Kind:        "hosted-model",
				Confidence:  0.98,
			},
		},
		Evaluations: []compliancedb.ControlEvaluation{
			{ControlID: "co.1", StatuteRef: "CO SB 24-205", Verdict: compliancedb.VerdictMet},
			{ControlID: "co.2", StatuteRef: "CO SB 24-205", Verdict: compliancedb.VerdictManual},
			{ControlID: "co.3", StatuteRef: "CO SB 24-205", Verdict: compliancedb.VerdictGap, GapMessage: "Missing bias test"},
		},
	}

	pkg, err := agent.CreatePackage(req)
	if err != nil {
		t.Fatalf("failed to create package: %v", err)
	}

	greenCount := 0
	yellowCount := 0
	redCount := 0

	for _, item := range pkg.Items {
		switch item.Status {
		case StatusGreenVerified:
			greenCount++
			if !item.IsLocked || !item.IsAnswered {
				t.Errorf("green item should be locked and answered: %+v", item)
			}
		case StatusYellowAttestationRequired:
			yellowCount++
			if item.IsLocked || item.IsAnswered {
				t.Errorf("yellow item should be unlocked and unanswered: %+v", item)
			}
		case StatusRedGap:
			redCount++
			if !item.RequiresAcknowledgement || item.IsAcknowledged {
				t.Errorf("red item should require acknowledgement: %+v", item)
			}
		}
	}

	if greenCount != 2 || yellowCount != 1 || redCount != 1 {
		t.Errorf("unexpected item distribution: green=%d, yellow=%d, red=%d", greenCount, yellowCount, redCount)
	}
}

func TestGateway_BlockCertificationUntilResolved(t *testing.T) {
	secret := []byte("test-secret-gateway-32bytes-long")
	agent := NewAgent(secret)

	req := CreatePackageRequest{
		RepoID:      "credit-scoring",
		Framework:   "colorado-ai-act",
		AIBOMSHA256: "aibom-sha-xyz",
		Evaluations: []compliancedb.ControlEvaluation{
			{ControlID: "co.manual.notice", StatuteRef: "CO SB 24-205", Verdict: compliancedb.VerdictManual},
			{ControlID: "co.gap.audit", StatuteRef: "CO SB 24-205", Verdict: compliancedb.VerdictGap, GapMessage: "Gap"},
		},
	}

	pkg, _ := agent.CreatePackage(req)

	// Obtain Human Token
	tokenStr, _, _ := GenerateHumanToken(secret, TokenRequest{UserID: "user-1", DocumentID: pkg.ID}, 90*time.Second)

	// 1. Attempt certification without answering Yellow or acknowledging Red -> BLOCKED
	_, err := agent.CertifyPackage(pkg.ID, CertifyRequest{
		UserID:                 "user-1",
		HumanConfirmationToken: tokenStr,
	})
	if err == nil || !strings.Contains(err.Error(), "certification blocked by unresolved items") {
		t.Errorf("expected certification to be blocked, got: %v", err)
	}

	// 2. Answer Yellow item
	yellowID := fmt.Sprintf("yellow-ctrl-%s", "co.manual.notice")
	if err := agent.UpdateYellowAnswer(pkg.ID, yellowID, "In-App Banner"); err != nil {
		t.Fatalf("failed to update yellow item: %v", err)
	}

	// Attempt certification with Yellow answered but Red still unacknowledged -> BLOCKED
	_, err = agent.CertifyPackage(pkg.ID, CertifyRequest{
		UserID:                 "user-1",
		HumanConfirmationToken: tokenStr,
	})
	if err == nil || !strings.Contains(err.Error(), "Unacknowledged Red gap") {
		t.Errorf("expected red gap blocker, got: %v", err)
	}

	// 3. Acknowledge Red gap
	redID := fmt.Sprintf("red-ctrl-%s", "co.gap.audit")
	if err := agent.AcknowledgeRedGap(pkg.ID, redID, "Remediation scheduled for Q3"); err != nil {
		t.Fatalf("failed to acknowledge red gap: %v", err)
	}

	// 4. Attempt certification with everything resolved -> SUCCESS
	certified, err := agent.CertifyPackage(pkg.ID, CertifyRequest{
		UserID:                 "user-1",
		UserTitle:              "Chief Compliance Officer",
		UserEmail:              "officer@acme.com",
		HumanConfirmationToken: tokenStr,
	})
	if err != nil {
		t.Fatalf("expected successful certification, got: %v", err)
	}

	if !certified.IsCertified || certified.CertifiedBy != "user-1" || certified.HTMLPayload == "" {
		t.Errorf("unexpected certified package state: %+v", certified)
	}

	// Verify Audit Log Entry
	auditLogs := agent.GetAuditLogs()
	if len(auditLogs) != 1 || auditLogs[0].DocumentID != pkg.ID || auditLogs[0].ActionType != "DOCUMENT_CERTIFIED" {
		t.Errorf("unexpected audit log: %+v", auditLogs)
	}
}

func TestHTTP_FullDocumentLifecycle_EndToEnd(t *testing.T) {
	secret := []byte("test-http-secret-32bytes-length-key")
	agent := NewAgent(secret)
	server := NewServer(agent)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	// 1. Healthz
	hResp, err := http.Get(ts.URL + "/healthz")
	if err != nil || hResp.StatusCode != http.StatusOK {
		t.Fatalf("healthz failed: %v", err)
	}
	_ = hResp.Body.Close()

	// 2. Create Document Package
	createReq := CreatePackageRequest{
		OrgName:     "Gotham Corp",
		RepoID:      "resume-ranker",
		RepoName:    "resume-ranker-aedt",
		CommitSHA:   "c-abc",
		Framework:   "nyc-ll144",
		AIBOMSHA256: "sha-nyc-1",
		Evaluations: []compliancedb.ControlEvaluation{
			{ControlID: "nyc.notice", StatuteRef: "NYC Admin Code", Verdict: compliancedb.VerdictManual},
		},
	}
	cBody, _ := json.Marshal(createReq)
	cResp, err := http.Post(ts.URL+"/api/v1/documents", "application/json", bytes.NewReader(cBody))
	if err != nil || cResp.StatusCode != http.StatusCreated {
		t.Fatalf("create document failed: %v", err)
	}

	var pkg DocumentPackage
	_ = json.NewDecoder(cResp.Body).Decode(&pkg)
	_ = cResp.Body.Close()

	// 3. Request Ephemeral Human Confirmation Token
	tokReq := TokenRequest{
		UserID:     "auditor-jane",
		UserEmail:  "jane@gotham.com",
		DocumentID: pkg.ID,
	}
	tBody, _ := json.Marshal(tokReq)
	tResp, err := http.Post(ts.URL+"/api/v1/auth/human-token", "application/json", bytes.NewReader(tBody))
	if err != nil || tResp.StatusCode != http.StatusOK {
		t.Fatalf("issue human token failed: %v", err)
	}

	var tokResp TokenResponse
	_ = json.NewDecoder(tResp.Body).Decode(&tokResp)
	_ = tResp.Body.Close()

	// 4. Update Yellow Item via HTTP
	yellowID := "yellow-ctrl-nyc.notice"
	yBody, _ := json.Marshal(map[string]string{"item_id": yellowID, "value": "10-day email disclosure"})
	client := &http.Client{}
	yReq, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/v1/documents/%s/yellow", ts.URL, pkg.ID), bytes.NewReader(yBody))
	yResp, err := client.Do(yReq)
	if err != nil || yResp.StatusCode != http.StatusOK {
		t.Fatalf("update yellow failed: %v", err)
	}
	_ = yResp.Body.Close()

	// 5. Certify Document Package via HTTP
	certReq := CertifyRequest{
		UserID:                 "auditor-jane",
		UserEmail:              "jane@gotham.com",
		UserTitle:              "Independent Auditor",
		HumanConfirmationToken: tokResp.Token,
		SignatureText:          "/s/ Jane Doe",
	}
	certBody, _ := json.Marshal(certReq)
	certResp, err := http.Post(fmt.Sprintf("%s/api/v1/documents/%s/certify", ts.URL, pkg.ID), "application/json", bytes.NewReader(certBody))
	if err != nil || certResp.StatusCode != http.StatusOK {
		t.Fatalf("certify failed: %v", err)
	}

	var certifiedPkg DocumentPackage
	_ = json.NewDecoder(certResp.Body).Decode(&certifiedPkg)
	_ = certResp.Body.Close()

	if !certifiedPkg.IsCertified || certifiedPkg.CertifiedBy != "auditor-jane" {
		t.Errorf("certification response mismatch: %+v", certifiedPkg)
	}

	// 6. Export HTML Package
	expResp, err := http.Get(fmt.Sprintf("%s/api/v1/documents/%s/export?format=html", ts.URL, pkg.ID))
	if err != nil || expResp.StatusCode != http.StatusOK {
		t.Fatalf("export html failed: %v", err)
	}
	_ = expResp.Body.Close()

	// 7. Verify Audit Log via HTTP
	auditResp, err := http.Get(ts.URL + "/api/v1/documents/audit-log")
	if err != nil || auditResp.StatusCode != http.StatusOK {
		t.Fatalf("get audit logs failed: %v", err)
	}
	var logs []FilingAuditEntry
	_ = json.NewDecoder(auditResp.Body).Decode(&logs)
	_ = auditResp.Body.Close()

	if len(logs) != 1 || logs[0].DocumentID != pkg.ID {
		t.Errorf("unexpected audit logs: %+v", logs)
	}
}

func TestDocument_EUAIAct_CertificationFlow(t *testing.T) {
	secret := []byte("test-eu-ai-act-secret-32bytes-len")
	agent := NewAgent(secret)

	req := CreatePackageRequest{
		OrgID:       "org-eu",
		OrgName:     "Acme Europe B.V.",
		RepoID:      "repo-eu-risk",
		RepoName:    "eu-risk-pipeline",
		CommitSHA:   "commit-eu-12345",
		Framework:   "eu-ai-act",
		AIBOMSHA256: "aibom-sha-eu-999",
		EvidenceIndex: map[report.EvidenceKey]report.EvidenceRef{
			"src/models/scoring.py:10": {
				AIBOMID:     "aibom-eu-1",
				FilePath:    "src/models/scoring.py",
				LineNumber:  10,
				ComponentID: "comp-eu-1",
				ModelName:   "openai/gpt-4o",
				Kind:        "hosted-llm",
				Confidence:  0.99,
			},
		},
	}

	pkg, err := agent.CreatePackage(req)
	if err != nil {
		t.Fatalf("CreatePackage failed: %v", err)
	}

	// Answer any yellow review item
	for _, item := range pkg.Items {
		if item.Status == StatusYellowAttestationRequired {
			_ = agent.UpdateYellowAnswer(pkg.ID, item.ID, "In-App Banner")
		}
	}

	tokenStr, _, err := GenerateHumanToken(secret, TokenRequest{
		UserID:     "officer-eu",
		UserEmail:  "officer@acme.eu",
		DocumentID: pkg.ID,
	}, 90*time.Second)
	if err != nil {
		t.Fatalf("GenerateHumanToken failed: %v", err)
	}

	certified, err := agent.CertifyPackage(pkg.ID, CertifyRequest{
		UserID:                 "officer-eu",
		UserEmail:              "officer@acme.eu",
		UserTitle:              "EU Compliance Officer",
		HumanConfirmationToken: tokenStr,
	})
	if err != nil {
		t.Fatalf("CertifyPackage failed: %v", err)
	}

	if !certified.IsCertified {
		t.Error("expected package to be certified")
	}
	if certified.Report == nil || certified.Report.Framework != "eu-ai-act" {
		t.Errorf("unexpected certified report: %+v", certified.Report)
	}
	if !strings.Contains(certified.MarkdownPayload, "EU AI Act Annex IV Technical Documentation") {
		t.Errorf("expected EU AI Act title in markdown, got: %s", certified.MarkdownPayload)
	}
}

func BenchmarkSecurity_TokenGenerationAndVerification(b *testing.B) {
	secret := []byte("bench-secret-gateway-32bytes-long")
	req := TokenRequest{
		UserID:     "user-bench",
		DocumentID: "doc-bench-100",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tokStr, _, _ := GenerateHumanToken(secret, req, 90*time.Second)
		_, _ = VerifyHumanToken(secret, tokStr, "doc-bench-100")
	}
}

func BenchmarkGateway_PackageCompilationAndCertification(b *testing.B) {
	secret := []byte("bench-secret-gateway-32bytes-long")
	agent := NewAgent(secret)
	req := CreatePackageRequest{
		RepoID:      "bench-repo",
		Framework:   "colorado-ai-act",
		AIBOMSHA256: "sha-bench",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkg, _ := agent.CreatePackage(req)
		tokenStr, _, _ := GenerateHumanToken(secret, TokenRequest{UserID: "u", DocumentID: pkg.ID}, 90*time.Second)
		_ = agent.UpdateYellowAnswer(pkg.ID, "yellow-notice-delivery", "In-App")
		_, _ = agent.CertifyPackage(pkg.ID, CertifyRequest{
			UserID:                 "u",
			HumanConfirmationToken: tokenStr,
		})
	}
}
