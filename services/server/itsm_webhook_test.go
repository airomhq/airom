package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestITSMConnector_DispatchJira_Success(t *testing.T) {
	var capturedAuth string
	var capturedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&capturedPayload)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"key":  "AIROM-101",
			"self": "https://jira.enterprise.internal/rest/api/2/issue/10001",
		})
	}))
	defer server.Close()

	cfg := ITSMConfig{
		JiraEnabled:    true,
		JiraURL:        server.URL,
		JiraUsername:   "audit-bot",
		JiraAPIToken:   "secret-token-xyz",
		JiraProjectKey: "GOV",
		JiraIssueType:  "Bug",
		AutoResolve:    true,
	}

	connector := NewITSMConnector(cfg, server.Client())

	inc := ComplianceIncident{
		ID:           "inc-99",
		RepoID:       "airomhq/core-ml",
		OrgID:        "org-enterprise",
		Framework:    "EU-AI-Act",
		ControlID:    "EU-AI-ART-50",
		ControlTitle: "Transparency Disclosures",
		Severity:     "High",
		Description:  "Generated AI content is served without synthetic watermarking metadata.",
		Status:       "gap",
		CreatedAt:    time.Now().UTC(),
	}

	resp, err := connector.DispatchIncident(context.Background(), inc)
	if err != nil {
		t.Fatalf("DispatchIncident failed: %v", err)
	}

	if len(resp) != 1 {
		t.Fatalf("expected 1 response, got %d", len(resp))
	}
	if resp[0].ExternalID != "AIROM-101" {
		t.Errorf("expected external ID AIROM-101, got %s", resp[0].ExternalID)
	}
	if capturedAuth == "" {
		t.Error("expected Basic Authorization header on Jira dispatch")
	}

	// Test Auto-Resolve Jira
	err = connector.AutoResolveIncident(context.Background(), "jira", "AIROM-101", "Added watermarking middleware in commit abc1234")
	if err != nil {
		t.Errorf("AutoResolveIncident failed: %v", err)
	}
}

func TestITSMConnector_DispatchServiceNow_Success(t *testing.T) {
	var capturedTable string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTable = r.URL.Path

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]string{
				"sys_id": "99f8d7e6c5b4a321",
				"number": "INC0099881",
			},
		})
	}))
	defer server.Close()

	cfg := ITSMConfig{
		ServiceNowEnabled:         true,
		ServiceNowURL:             server.URL,
		ServiceNowUsername:        "snow-admin",
		ServiceNowPassword:        "snow-pass",
		ServiceNowTable:           "incident",
		ServiceNowAssignmentGroup: "AI Security Operations",
		AutoResolve:               true,
	}

	connector := NewITSMConnector(cfg, server.Client())

	inc := ComplianceIncident{
		ID:           "inc-100",
		RepoID:       "airomhq/rag-agent",
		OrgID:        "org-enterprise",
		Framework:    "CO-SB-24-205",
		ControlID:    "CO-SB-RISK-MGMT",
		ControlTitle: "Algorithmic Risk Management Program",
		Severity:     "Critical",
		Description:  "Algorithmic impact assessment missing for consequential decision model.",
		Status:       "gap",
		CreatedAt:    time.Now().UTC(),
	}

	resp, err := connector.DispatchIncident(context.Background(), inc)
	if err != nil {
		t.Fatalf("DispatchIncident failed: %v", err)
	}

	if len(resp) != 1 {
		t.Fatalf("expected 1 response, got %d", len(resp))
	}
	if resp[0].ExternalID != "INC0099881" {
		t.Errorf("expected external ID INC0099881, got %s", resp[0].ExternalID)
	}
	if capturedTable != "/api/now/table/incident" {
		t.Errorf("expected ServiceNow table path /api/now/table/incident, got %s", capturedTable)
	}

	// Test Auto-Resolve ServiceNow
	err = connector.AutoResolveIncident(context.Background(), "servicenow", "99f8d7e6c5b4a321", "Impact assessment attached and verified")
	if err != nil {
		t.Errorf("AutoResolveIncident failed: %v", err)
	}
}
