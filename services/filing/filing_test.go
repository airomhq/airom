package filing

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFiling_PackageBuilder_AllJurisdictions(t *testing.T) {
	builder := NewPackageBuilder()

	jurisdictions := []Jurisdiction{
		JurisdictionColorado,
		JurisdictionCalifornia,
		JurisdictionNYC,
		JurisdictionEU,
		JurisdictionIllinois,
		JurisdictionTexas,
		JurisdictionVirginia,
	}

	for _, j := range jurisdictions {
		opts := BuildPackageOptions{
			Jurisdiction:     j,
			OrganizationID:   "org_enterprise_corp",
			OrganizationName: "Enterprise AI Solutions Inc.",
			RepositoryID:     "repo_frontier_ai",
			SnapshotID:       "snap_abc123",
			SystemName:       "Frontier Decision Engine v4",
			SystemPurpose:    "Consequential credit decisioning & risk analysis",
			ModelIDs:         []string{"gpt-4o", "claude-3-5-sonnet"},
			SignerName:       "Dr. Jane Doe",
			SignerTitle:      "Chief Compliance Officer",
			SignerEmail:      "jane.doe@enterprise.com",
			AuditDate:        time.Now().UTC(),
			ControlsMetCount: 18,
			ControlsGapCount: 0,
		}

		manifest, err := builder.BuildPackage(opts)
		if err != nil {
			t.Fatalf("[%s] BuildPackage failed: %v", j, err)
		}

		if manifest.PackageID == "" {
			t.Errorf("[%s] Expected non-empty PackageID", j)
		}
		if manifest.PackageChecksum == "" {
			t.Errorf("[%s] Expected non-empty PackageChecksum", j)
		}
		if manifest.Signer.SignatureHash == "" {
			t.Errorf("[%s] Expected non-empty Signer SignatureHash", j)
		}
		if len(manifest.Artifacts) == 0 {
			t.Errorf("[%s] Expected at least 1 constituent artifact", j)
		}

		for _, art := range manifest.Artifacts {
			if art.SHA256 == "" {
				t.Errorf("[%s] Artifact %s has empty SHA256", j, art.RelativePath)
			}
			if len(art.Content) == 0 {
				t.Errorf("[%s] Artifact %s has empty Content", j, art.RelativePath)
			}
			if art.SizeBytes != int64(len(art.Content)) {
				t.Errorf("[%s] Artifact %s size mismatch: %d != %d", j, art.RelativePath, art.SizeBytes, len(art.Content))
			}
		}
	}
}

func TestFiling_PackageVerification_OnDisk(t *testing.T) {
	builder := NewPackageBuilder()
	agent := NewFilingAgent(nil)

	opts := BuildPackageOptions{
		Jurisdiction:     JurisdictionColorado,
		OrganizationID:   "org_verif_test",
		OrganizationName: "Verif Corp",
		RepositoryID:     "repo_main",
		SnapshotID:       "snap_111",
		SignerName:       "John Officer",
		SignerTitle:      "VP of AI Ethics",
		SignerEmail:      "john@verif.com",
		ModelIDs:         []string{"gpt-4o"},
		ControlsMetCount: 10,
		ControlsGapCount: 0,
	}

	manifest, err := builder.BuildPackage(opts)
	if err != nil {
		t.Fatalf("failed to build package: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "airom-filing-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	if err := builder.ExportToDirectory(manifest, tempDir); err != nil {
		t.Fatalf("failed to export package to directory: %v", err)
	}

	// Verify genuine package
	verifiedManifest, err := agent.VerifyPackage(tempDir)
	if err != nil {
		t.Fatalf("VerifyPackage failed on pristine package: %v", err)
	}
	if verifiedManifest.PackageChecksum != manifest.PackageChecksum {
		t.Errorf("expected package checksum %s, got %s", manifest.PackageChecksum, verifiedManifest.PackageChecksum)
	}

	// Adversarial Tampering: Corrupt one byte of an artifact
	corruptFile := filepath.Join(tempDir, manifest.Artifacts[0].RelativePath)
	if err := os.WriteFile(corruptFile, []byte("MALICIOUS_TAMPERED_CONTENT"), 0o644); err != nil {
		t.Fatalf("failed to tamper file: %v", err)
	}

	_, err = agent.VerifyPackage(tempDir)
	if err == nil {
		t.Fatal("expected VerifyPackage to fail-closed on tampered artifact file, but got no error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") && !strings.Contains(err.Error(), "size mismatch") {
		t.Errorf("expected checksum mismatch error, got: %v", err)
	}
}

func TestFiling_StatePortalSubmission_MockServer(t *testing.T) {
	var receivedPayload FilingManifest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Filing-Jurisdiction") != string(JurisdictionColorado) {
			http.Error(w, "missing or invalid jurisdiction header", http.StatusBadRequest)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ack_token": "CO-AG-RECEIPT-2026-998811",
			"status":    "ACCEPTED",
			"message":   "Filing received and queued for attorney general compliance review.",
		})
	}))
	defer server.Close()

	builder := NewPackageBuilder()
	agent := NewFilingAgent(server.Client())

	opts := BuildPackageOptions{
		Jurisdiction:     JurisdictionColorado,
		OrganizationID:   "org_submit_test",
		OrganizationName: "Submit Corp",
		RepositoryID:     "repo_ai_engine",
		SignerName:       "Alice Submitter",
		SignerEmail:      "alice@submit.com",
	}

	manifest, err := builder.BuildPackage(opts)
	if err != nil {
		t.Fatalf("failed to build package: %v", err)
	}

	receipt, err := agent.SubmitPackage(context.Background(), manifest, server.URL)
	if err != nil {
		t.Fatalf("SubmitPackage failed: %v", err)
	}

	if receipt.AcknowledgmentToken != "CO-AG-RECEIPT-2026-998811" {
		t.Errorf("expected ack token CO-AG-RECEIPT-2026-998811, got %s", receipt.AcknowledgmentToken)
	}
	if receipt.Status != StatusAcknowledged {
		t.Errorf("expected status ACKNOWLEDGED, got %s", receipt.Status)
	}

	// Verify receipt stored in agent ledger
	receipts := agent.GetReceipts("org_submit_test")
	if len(receipts) != 1 {
		t.Fatalf("expected 1 stored receipt, got %d", len(receipts))
	}
	if receipts[0].ReceiptID != receipt.ReceiptID {
		t.Errorf("expected receipt ID %s, got %s", receipt.ReceiptID, receipts[0].ReceiptID)
	}
}

func TestFiling_RenewalCalendar_DeadlinesAndUrgency(t *testing.T) {
	engine := NewRenewalEngine()
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	// Setup historical filing map
	history := FilingHistoryMap{
		JurisdictionColorado:   now.AddDate(0, 0, -370), // Filed 370 days ago -> OVERDUE (-5 days)
		JurisdictionNYC:        now.AddDate(0, 0, -360), // Filed 360 days ago -> UPCOMING_7D (5 days left)
		JurisdictionCalifornia: now.AddDate(0, 0, -345), // Filed 345 days ago -> UPCOMING_30D (20 days left)
		JurisdictionEU:         now.AddDate(0, 0, -285), // Filed 285 days ago -> UPCOMING_90D (80 days left)
		JurisdictionIllinois:   now.AddDate(0, 0, -100), // Filed 100 days ago -> CURRENT (265 days left)
	}

	// Substantial modification in Texas 85 days ago -> Requires review within 90 days (5 days left -> UPCOMING_7D)
	subModTime := now.AddDate(0, 0, -85)
	mods := SubstantialModMap{
		JurisdictionTexas: subModTime,
	}

	calendar := engine.ComputeCalendar("org_cal_test", history, mods, now)

	if calendar.OverdueCount < 1 {
		t.Errorf("expected at least 1 overdue item (Colorado), got %d", calendar.OverdueCount)
	}
	if calendar.UrgentCount < 2 {
		t.Errorf("expected at least 2 urgent items (NYC, Texas), got %d", calendar.UrgentCount)
	}

	table := engine.RenderCalendarTable(calendar)
	if !strings.Contains(table, "AIROM STATUTORY COMPLIANCE RENEWAL CALENDAR") {
		t.Error("rendered table missing title banner")
	}
	if !strings.Contains(table, "OVERDUE") {
		t.Error("rendered table missing OVERDUE alert")
	}
}

func TestFiling_Service_REST_API(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	client := ts.Client()

	// 1. POST /api/v1/filings/generate
	opts := BuildPackageOptions{
		Jurisdiction:     JurisdictionNYC,
		OrganizationID:   "org_api_test",
		OrganizationName: "API Corp",
		RepositoryID:     "repo_nyc",
		SignerName:       "Chief Officer",
		SignerEmail:      "chief@api.com",
	}
	body, _ := json.Marshal(opts)

	resp, err := client.Post(ts.URL+"/api/v1/filings/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("generate request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected HTTP 201 Created, got %d", resp.StatusCode)
	}

	var manifest FilingManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		t.Fatalf("failed to decode manifest: %v", err)
	}
	if manifest.Jurisdiction != JurisdictionNYC {
		t.Errorf("expected NYC jurisdiction, got %s", manifest.Jurisdiction)
	}

	// 2. POST /api/v1/filings/submit
	submitPayload := map[string]interface{}{
		"manifest": manifest,
	}
	submitBody, _ := json.Marshal(submitPayload)
	submitResp, err := client.Post(ts.URL+"/api/v1/filings/submit", "application/json", bytes.NewReader(submitBody))
	if err != nil {
		t.Fatalf("submit request failed: %v", err)
	}
	defer func() { _ = submitResp.Body.Close() }()

	if submitResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK from submit, got %d", submitResp.StatusCode)
	}

	var receipt FilingReceipt
	if err := json.NewDecoder(submitResp.Body).Decode(&receipt); err != nil {
		t.Fatalf("failed to decode receipt: %v", err)
	}
	if receipt.Status != StatusVerified {
		t.Errorf("expected status VERIFIED, got %s", receipt.Status)
	}

	// 3. GET /api/v1/calendar?org=org_api_test
	calResp, err := client.Get(ts.URL + "/api/v1/calendar?org=org_api_test")
	if err != nil {
		t.Fatalf("calendar request failed: %v", err)
	}
	defer func() { _ = calResp.Body.Close() }()

	if calResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK for calendar, got %d", calResp.StatusCode)
	}

	var cal RenewalCalendar
	if err := json.NewDecoder(calResp.Body).Decode(&cal); err != nil {
		t.Fatalf("failed to decode calendar: %v", err)
	}
	if len(cal.Items) == 0 {
		t.Error("expected non-empty calendar items")
	}

	// 4. GET /healthz
	healthResp, err := client.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer func() { _ = healthResp.Body.Close() }()

	if healthResp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 for healthz, got %d", healthResp.StatusCode)
	}
}
