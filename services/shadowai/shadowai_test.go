package shadowai

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestShadowAI_Detector_AllSignatures(t *testing.T) {
	detector := NewShadowAIDetector()

	files := []FileEntry{
		{
			Path:    "src/config/.env.local",
			Content: "OPENAI_API_KEY=sk-proj-9928172635481928374650192837465\nDATABASE_URL=postgres://...",
		},
		{
			Path:    "packages/agent/client.ts",
			Content: "const anthropicKey = 'sk-ant-api03-abcdef1234567890abcdef123456';",
		},
		{
			Path:    ".cursorrules",
			Content: "You are an expert TypeScript engineer following enterprise standards.",
		},
		{
			Path:    ".vscode/settings.json",
			Content: `{"github.copilot.advanced": {"inlineSuggest.enable": true}}`,
		},
		{
			Path:    "scripts/notion_sync.py",
			Content: "NOTION_TOKEN = 'ntn_1234567890abcdef1234567890'\nNOTION_AI_API = 'https://api.notion.com/v1/ai'",
		},
		{
			Path:    ".github/workflows/ci.yml",
			Content: "env:\n  HUGGINGFACE_TOKEN: hf_9876543210abcdef9876543210",
		},
	}

	opts := DetectorOptions{
		OrganizationID: "org_test_detector",
	}

	inventory, err := detector.ScanFiles(files, opts)
	if err != nil {
		t.Fatalf("ScanFiles failed: %v", err)
	}

	if inventory.InventoryID == "" {
		t.Error("expected non-empty InventoryID")
	}
	if inventory.TotalDiscovered < 6 {
		t.Errorf("expected at least 6 shadow AI discoveries, got %d", inventory.TotalDiscovered)
	}
	if inventory.CriticalCount < 2 {
		t.Errorf("expected at least 2 critical findings (OpenAI, Anthropic), got %d", inventory.CriticalCount)
	}
	if inventory.InventoryHash == "" {
		t.Error("expected non-empty InventoryHash")
	}

	for _, f := range inventory.Findings {
		if f.FindingHash == "" {
			t.Errorf("finding %s has empty hash", f.FindingID)
		}
		if f.PolicyViolation == "" {
			t.Errorf("finding %s missing policy violation", f.FindingID)
		}
		if f.RemediationAction == "" {
			t.Errorf("finding %s missing remediation action", f.FindingID)
		}
	}
}

func TestShadowAI_ApprovedPlatforms_Whitelisting(t *testing.T) {
	detector := NewShadowAIDetector()

	files := []FileEntry{
		{
			Path:    ".cursorrules",
			Content: "Rule definitions",
		},
		{
			Path:    "src/llm.py",
			Content: "OPENAI_API_KEY=sk-proj-12345678901234567890123456",
		},
	}

	// Whitelist Cursor and OpenAI
	opts := DetectorOptions{
		OrganizationID:    "org_whitelist",
		ApprovedPlatforms: []SaaSPlatform{PlatformCursor, PlatformOpenAI},
	}

	inventory, err := detector.ScanFiles(files, opts)
	if err != nil {
		t.Fatalf("ScanFiles failed: %v", err)
	}

	if inventory.ApprovedCount != 2 {
		t.Errorf("expected 2 approved findings, got %d", inventory.ApprovedCount)
	}
	if inventory.CriticalCount != 0 {
		t.Errorf("expected 0 critical findings when whitelisted, got %d", inventory.CriticalCount)
	}
}

func TestShadowAI_DashboardRenderer(t *testing.T) {
	detector := NewShadowAIDetector()
	files := []FileEntry{
		{
			Path:    ".cursorrules",
			Content: "content",
		},
	}
	inv, _ := detector.ScanFiles(files, DetectorOptions{OrganizationID: "org_render"})

	dash := RenderInventoryDashboard(inv)
	if !strings.Contains(dash, "AIROM SHADOW AI & SAAS CONNECTOR ASSET INVENTORY") {
		t.Error("dashboard missing title banner")
	}
	if !strings.Contains(dash, "CURSOR_AI") {
		t.Error("dashboard missing CURSOR_AI platform row")
	}
}

func TestShadowAI_REST_API(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	client := ts.Client()

	reqPayload := map[string]interface{}{
		"organization_id": "org_api_shadow",
		"files": []map[string]string{
			{
				"path":    ".cursorrules",
				"content": "rule",
			},
		},
	}
	body, _ := json.Marshal(reqPayload)

	resp, err := client.Post(ts.URL+"/api/v1/shadowai/scan", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("scan request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected HTTP 201 Created, got %d", resp.StatusCode)
	}

	var inv ShadowAIInventory
	if err := json.NewDecoder(resp.Body).Decode(&inv); err != nil {
		t.Fatalf("failed to decode inventory: %v", err)
	}
	if inv.TotalDiscovered != 1 {
		t.Errorf("expected 1 discovery, got %d", inv.TotalDiscovered)
	}

	// Health check
	hResp, err := client.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz failed: %v", err)
	}
	defer func() { _ = hResp.Body.Close() }()

	if hResp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 for healthz, got %d", hResp.StatusCode)
	}
}
