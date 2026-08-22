package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/services/audit"
	"github.com/airomhq/airom/services/auth"
	"github.com/airomhq/airom/services/billing"
	"github.com/airomhq/airom/services/compliancedb"
	"github.com/airomhq/airom/services/document"
	"github.com/airomhq/airom/services/report"
)

func TestEnterpriseServer_HealthAndProbes(t *testing.T) {
	cfg := DefaultConfig()
	srv := NewEnterpriseServer(cfg)
	defer func() { _ = srv.Shutdown(context.Background()) }()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. /healthz
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /healthz, got: resp=%+v, err=%v", resp, err)
	}
	_ = resp.Body.Close()

	// 2. /readyz
	resp, err = http.Get(ts.URL + "/readyz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /readyz, got: resp=%+v, err=%v", resp, err)
	}
	var readyBody map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&readyBody)
	_ = resp.Body.Close()
	if readyBody["status"] != "ready" {
		t.Errorf("unexpected readyz status: %+v", readyBody)
	}

	// 3. /metrics
	resp, err = http.Get(ts.URL + "/metrics")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /metrics, got: resp=%+v, err=%v", resp, err)
	}
	metricsBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(metricsBytes), "airom_server_up 1") {
		t.Errorf("missing expected prometheus metric in /metrics: %s", string(metricsBytes))
	}

	// 4. /api/v1/info
	resp, err = http.Get(ts.URL + "/api/v1/info")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/info, got: resp=%+v, err=%v", resp, err)
	}
	var infoBody map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&infoBody)
	_ = resp.Body.Close()
	if infoBody["edition"] != "Enterprise" {
		t.Errorf("unexpected info edition: %+v", infoBody)
	}
}

func TestEnterpriseServer_FullLifecycleE2E(t *testing.T) {
	cfg := DefaultConfig()
	srv := NewEnterpriseServer(cfg)
	defer func() { _ = srv.Shutdown(context.Background()) }()

	ctx := context.Background()
	orgID := "org-enterprise-acme"
	repoID := "repo-facial-rec-platform"

	// STEP 1: Enterprise SSO Provisioning & API Key Minting
	authSvc := srv.Auth()
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	rawKey := "airom_live_acmetestkey1234567890abcdef"
	rawHashBytes := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(rawHashBytes[:])

	apiKey := auth.APIKey{
		ID:        "key-acme-ci",
		OrgID:     orgID,
		KeyPrefix: rawKey[:18],
		KeyHash:   keyHash,
		Name:      "deploy-ci-runner",
		Role:      auth.RoleAdmin,
		Permissions: []auth.Permission{
			auth.PermScanWrite, auth.PermReportGenerate, auth.PermDocumentCertify, auth.PermLedgerVerify,
		},
		CreatedAt: time.Now().UTC(),
		ExpiresAt: &expires,
		IsActive:  true,
	}
	authSvc.RegisterAPIKey(apiKey)

	// STEP 2: Stripe Billing Setup & Enterprise Quota Activation
	billingSvc := srv.Billing()
	billingSvc.ProvisionAccount(billing.CustomerAccount{
		OrgID:            orgID,
		StripeCustomerID: "cus_acme_987",
		Tier:             billing.TierEnterprise,
		Status:           billing.StatusActive,
	})

	if err := billingSvc.CheckScanAllowed(orgID); err != nil {
		t.Fatalf("enterprise scan should be allowed: %v", err)
	}
	if err := billingSvc.CheckFeatureAllowed(orgID, "siem_streaming"); err != nil {
		t.Fatalf("enterprise SIEM streaming should be allowed: %v", err)
	}

	// STEP 3: Ingest AIBOM Snapshot into ComplianceDB Hash Chain Ledger
	compDB := srv.ComplianceDB()
	compDB.RegisterOrg(compliancedb.Organization{
		ID:        orgID,
		Name:      "Acme AI Inc",
		CreatedAt: time.Now().UTC(),
	})
	compDB.RegisterRepo(compliancedb.Repository{
		ID:        repoID,
		OrgID:     orgID,
		CreatedAt: time.Now().UTC(),
	})

	ingestReq := compliancedb.IngestionRequest{
		RepoID:          repoID,
		CommitSHA:       "sha256-acme-commit-001",
		Branch:          "main",
		ScanTimestamp:   time.Now().UTC(),
		ComponentsCount: 42,
		ControlsMet:     1,
		ControlsGap:     0,
	}
	reqBody, _ := json.Marshal(ingestReq)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/repos/"+repoID+"/snapshots", bytes.NewReader(reqBody))
	compDB.IngestSnapshotHandler(rec, httpReq, repoID)

	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to ingest snapshot via handler: status=%d, body=%s", rec.Code, rec.Body.String())
	}

	// Record Scan Consumption in Billing
	if err := billingSvc.RecordScanUsage(orgID); err != nil {
		t.Fatalf("failed to record billing scan usage: %v", err)
	}
	usage := billingSvc.GetUsage(orgID)
	if usage.ScansCount != 1 {
		t.Errorf("expected 1 recorded scan in billing, got %d", usage.ScansCount)
	}

	// STEP 4: Report Generation with AST Evidence Grounding (Illinois BIPA)
	evIndex := map[report.EvidenceKey]report.EvidenceRef{
		"src/vision/face.py:44": {
			AIBOMID:     "aibom-acme-1",
			FilePath:    "src/vision/face.py",
			LineNumber:  44,
			ComponentID: "comp_face_01",
			ModelName:   "facenet-embeddings",
			Kind:        "local-model-file",
			Confidence:  0.98,
		},
	}
	reportReq := report.ReportRequest{
		OrgID:         orgID,
		OrgName:       "Acme AI Inc",
		RepoID:        repoID,
		RepoName:      "facial-rec-platform",
		CommitSHA:     "sha256-acme-commit-001",
		Framework:     "illinois-bipa",
		EvidenceIndex: evIndex,
	}

	bipaRep, err := report.GenerateBIPAReport(reportReq, nil)
	if err != nil {
		t.Fatalf("failed to generate BIPA report: %v", err)
	}
	if !bipaRep.AllCitationsValid || len(bipaRep.Sections) != 4 {
		t.Fatalf("invalid BIPA report structure: %+v", bipaRep)
	}

	// STEP 5: Document Review Gateway & Ephemeral HMAC Certification
	docAgent := srv.Document()
	pkg, err := docAgent.CreatePackage(document.CreatePackageRequest{
		OrgID:         orgID,
		RepoID:        repoID,
		CommitSHA:     "sha256-acme-commit-001",
		Framework:     "illinois-bipa",
		EvidenceIndex: evIndex,
	})
	if err != nil {
		t.Fatalf("failed to create review package: %v", err)
	}

	// Mint 90s Ephemeral Token
	tokenStr, _, err := document.GenerateHumanToken([]byte(cfg.HumanTokenSecret), document.TokenRequest{
		UserID:     "cpo-001",
		UserEmail:  "cpo@acme.com",
		DocumentID: pkg.ID,
	}, 90*time.Second)
	if err != nil {
		t.Fatalf("failed to issue human review token: %v", err)
	}

	// Certify Document using Token
	certReq := document.CertifyRequest{
		UserID:                 "cpo-001",
		UserEmail:              "cpo@acme.com",
		UserTitle:              "Chief Privacy Officer",
		HumanConfirmationToken: tokenStr,
		YellowAnswers: map[string]string{
			"yellow-notice-delivery": "Verified written retention schedule published.",
		},
		SignatureText: "Sarah Jenkins, Esq.",
	}
	certifiedDoc, err := docAgent.CertifyPackage(pkg.ID, certReq)
	if err != nil {
		t.Fatalf("failed to certify document: %v", err)
	}
	if !certifiedDoc.IsCertified {
		t.Errorf("expected certified document status, got: %+v", certifiedDoc)
	}

	// STEP 6: SOC 2 Audit Logging & SIEM Event Streaming
	auditSvc := srv.Audit()
	auditEvt := audit.AuditEvent{
		OrgID:       orgID,
		UserID:      "cpo@acme.com",
		Action:      "DOCUMENT_CERTIFIED",
		Resource:    fmt.Sprintf("doc:%s", certifiedDoc.ID),
		Severity:    audit.SeverityHigh,
		SOC2Control: audit.SOC2_CC6_6,
		IPAddress:   "10.0.0.1",
		Details: map[string]interface{}{
			"framework":   "illinois-bipa",
			"document_id": certifiedDoc.ID,
		},
	}
	recordedEvt, err := auditSvc.RecordEvent(ctx, auditEvt)
	if err != nil {
		t.Fatalf("failed to record SOC 2 audit event: %v", err)
	}
	if !recordedEvt.VerifySignature(cfg.AuditSigningKey) {
		t.Errorf("SOC 2 HMAC signature verification failed")
	}

	// Verify Audit Event Retrieval
	events := auditSvc.GetEvents(orgID)
	if len(events) != 1 || events[0].Action != "DOCUMENT_CERTIFIED" {
		t.Errorf("unexpected audit event history: %+v", events)
	}
}
