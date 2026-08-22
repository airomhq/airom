package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type mockHTTPClient struct {
	lastReq    *http.Request
	lastBody   []byte
	statusCode int
	err        error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	body, _ := io.ReadAll(req.Body)
	m.lastReq = req
	m.lastBody = body

	resp := &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"status":"ok"}`))),
		Header:     make(http.Header),
	}
	return resp, nil
}

func TestAudit_RecordAndHMACVerification(t *testing.T) {
	signingKey := "soc2-super-secret-signing-key-2026"
	svc := NewService(signingKey, nil)
	defer svc.Close()

	ctx := context.Background()
	evt := AuditEvent{
		OrgID:       "org-enterprise-1",
		UserID:      "cpo@enterprise.com",
		Action:      "DOCUMENT_CERTIFIED",
		Resource:    "doc:bipa-rep-001",
		Severity:    SeverityHigh,
		SOC2Control: SOC2_CC6_6,
		IPAddress:   "192.168.1.50",
		Details: map[string]interface{}{
			"statute": "740 ILCS 14/",
		},
	}

	recorded, err := svc.RecordEvent(ctx, evt)
	if err != nil {
		t.Fatalf("failed to record event: %v", err)
	}

	if recorded.Signature == "" {
		t.Errorf("expected non-empty HMAC signature")
	}

	// Verify authentic signature
	if !recorded.VerifySignature(signingKey) {
		t.Errorf("signature verification failed for authentic event")
	}

	// Test tamper detection: change action
	tampered := *recorded
	tampered.Action = "MALICIOUS_TAMPER"
	if tampered.VerifySignature(signingKey) {
		t.Errorf("tamper detection failed: modified action passed signature check")
	}

	// Test wrong key
	if recorded.VerifySignature("wrong-secret-key") {
		t.Errorf("expected failure when verifying with wrong key")
	}
}

func TestSIEM_DatadogPayloadAndDelivery(t *testing.T) {
	signingKey := "signing-key"
	mockClient := &mockHTTPClient{statusCode: 202}
	svc := NewService(signingKey, mockClient)
	defer svc.Close()

	orgID := "org-datadog-test"
	cfg := SIEMConfig{
		OrgID:       orgID,
		Destination: SIEMDatadog,
		EndpointURL: "https://http-intake.logs.datadoghq.com/api/v2/logs",
		APIKey:      "dd-api-key-test-12345",
		Enabled:     true,
	}
	if err := svc.ConfigureSIEM(cfg); err != nil {
		t.Fatalf("failed to configure datadog SIEM: %v", err)
	}

	evt := AuditEvent{
		ID:          "evt-dd-101",
		OrgID:       orgID,
		UserID:      "admin@org.com",
		Action:      "KEY_ROTATED",
		Resource:    "key:airom_live_xyz",
		Severity:    SeverityCritical,
		SOC2Control: SOC2_CC6_1,
		Timestamp:   time.Now().UTC(),
	}

	err := svc.StreamEvent(context.Background(), &evt)
	if err != nil {
		t.Fatalf("failed to stream datadog event: %v", err)
	}

	if mockClient.lastReq.Header.Get("DD-API-KEY") != "dd-api-key-test-12345" {
		t.Errorf("missing or invalid DD-API-KEY header: %s", mockClient.lastReq.Header.Get("DD-API-KEY"))
	}

	var ddEvt DatadogEvent
	if err := json.Unmarshal(mockClient.lastBody, &ddEvt); err != nil {
		t.Fatalf("failed to unmarshal datadog body: %v", err)
	}
	if ddEvt.DDSource != "airom-governance" || ddEvt.Status != "critical" {
		t.Errorf("unexpected datadog payload format: %+v", ddEvt)
	}
}

func TestSIEM_SplunkHECPayloadAndDelivery(t *testing.T) {
	signingKey := "signing-key"
	mockClient := &mockHTTPClient{statusCode: 200}
	svc := NewService(signingKey, mockClient)
	defer svc.Close()

	orgID := "org-splunk-test"
	cfg := SIEMConfig{
		OrgID:       orgID,
		Destination: SIEMSplunk,
		EndpointURL: "https://splunk-hec.enterprise.internal:8088/services/collector/event",
		APIKey:      "splunk-hec-token-999",
		Enabled:     true,
	}
	if err := svc.ConfigureSIEM(cfg); err != nil {
		t.Fatalf("failed to configure splunk SIEM: %v", err)
	}

	evt := AuditEvent{
		ID:          "evt-splunk-202",
		OrgID:       orgID,
		UserID:      "dev@org.com",
		Action:      "SCAN_EXECUTED",
		Resource:    "repo:financial-pipeline",
		Severity:    SeverityInfo,
		SOC2Control: SOC2_CC6_8,
		Timestamp:   time.Now().UTC(),
	}

	err := svc.StreamEvent(context.Background(), &evt)
	if err != nil {
		t.Fatalf("failed to stream splunk event: %v", err)
	}

	if mockClient.lastReq.Header.Get("Authorization") != "Splunk splunk-hec-token-999" {
		t.Errorf("missing or invalid Authorization header: %s", mockClient.lastReq.Header.Get("Authorization"))
	}

	var splunkEvt SplunkHECEvent
	if err := json.Unmarshal(mockClient.lastBody, &splunkEvt); err != nil {
		t.Fatalf("failed to unmarshal splunk body: %v", err)
	}
	if splunkEvt.Source != "airom:compliance" {
		t.Errorf("unexpected splunk source: %s", splunkEvt.Source)
	}
}

func TestSIEM_WebhookHMACSignature(t *testing.T) {
	signingKey := "signing-key"
	mockClient := &mockHTTPClient{statusCode: 200}
	svc := NewService(signingKey, mockClient)
	defer svc.Close()

	orgID := "org-webhook-test"
	webhookSecret := "webhook-hmac-secret-777"
	cfg := SIEMConfig{
		OrgID:       orgID,
		Destination: SIEMWebhook,
		EndpointURL: "https://siem.customer.com/webhooks/airom",
		SecretKey:   webhookSecret,
		Enabled:     true,
	}
	_ = svc.ConfigureSIEM(cfg)

	evt := AuditEvent{
		ID:          "evt-wh-303",
		OrgID:       orgID,
		Action:      "SECURITY_INCIDENT_RESOLVED",
		Resource:    "incident:inc-009",
		Severity:    SeverityMedium,
		SOC2Control: SOC2_CC7_2,
		Timestamp:   time.Now().UTC(),
	}

	err := svc.StreamEvent(context.Background(), &evt)
	if err != nil {
		t.Fatalf("failed to stream webhook event: %v", err)
	}

	sigHeader := mockClient.lastReq.Header.Get("X-AIROM-Signature")
	if !strings.HasPrefix(sigHeader, "sha256=") {
		t.Errorf("missing or invalid X-AIROM-Signature: %s", sigHeader)
	}
}

func TestAudit_REST_API_Lifecycle(t *testing.T) {
	signingKey := "test-signing-key"
	svc := NewService(signingKey, nil)
	defer svc.Close()

	server := httptest.NewServer(svc.Routes())
	defer server.Close()

	// 1. Ingest Audit Event
	payload := `{"org_id":"org-rest-1","action":"AUTH_LOGIN","resource":"user:alice","severity":"INFO","soc2_control":"CC6.1_LOGICAL_ACCESS"}`
	resp, err := http.Post(server.URL+"/api/v1/audit/events/ingest", "application/json", strings.NewReader(payload))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("failed to ingest event via REST: resp=%+v, err=%v", resp, err)
	}

	// 2. Query Audit Events
	resp, err = http.Get(server.URL + "/api/v1/audit/events?org_id=org-rest-1")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to query events: resp=%+v, err=%v", resp, err)
	}
	var res struct {
		Events []AuditEvent `json:"events"`
		Total  int          `json:"total"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res.Total != 1 || res.Events[0].Action != "AUTH_LOGIN" {
		t.Errorf("unexpected query result: %+v", res)
	}

	// 3. Configure SIEM
	cfgPayload := `{"org_id":"org-rest-1","destination":"datadog","endpoint_url":"https://logs.datadog.com","api_key":"secret12345","enabled":true}`
	resp, err = http.Post(server.URL+"/api/v1/audit/siem/config", "application/json", strings.NewReader(cfgPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to configure SIEM via REST: resp=%+v, err=%v", resp, err)
	}

	// 4. Retrieve SIEM Config (masked secret)
	resp, err = http.Get(server.URL + "/api/v1/audit/siem/config/get?org_id=org-rest-1")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to get SIEM config: resp=%+v, err=%v", resp, err)
	}
	var fetchedCfg SIEMConfig
	_ = json.NewDecoder(resp.Body).Decode(&fetchedCfg)
	if fetchedCfg.APIKey != "se*******45" {
		t.Errorf("expected masked API key 'se*******45', got %s", fetchedCfg.APIKey)
	}
}
