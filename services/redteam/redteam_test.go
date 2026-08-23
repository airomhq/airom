package redteam

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedTeam_ExecuteAssessment_AllDefended(t *testing.T) {
	engine := NewRedTeamEngine()

	assessment, err := engine.ExecuteAssessment(context.Background(), "https://api.gateway.internal", "claude-3-5-sonnet", nil)
	if err != nil {
		t.Fatalf("ExecuteAssessment failed: %v", err)
	}

	if assessment.AssessmentID == "" {
		t.Error("expected non-empty AssessmentID")
	}
	if assessment.DefendedCount != assessment.TotalProbes {
		t.Errorf("expected all %d probes defended, got %d", assessment.TotalProbes, assessment.DefendedCount)
	}
	if assessment.DefenseRateScore != 100.0 {
		t.Errorf("expected 100%% defense score, got %.1f%%", assessment.DefenseRateScore)
	}
	if assessment.AssessmentChecksum == "" {
		t.Error("expected non-empty AssessmentChecksum")
	}
}

func TestRedTeam_ExecuteAssessment_VulnerabilityDetection(t *testing.T) {
	engine := NewRedTeamEngine()

	simulatedExploits := map[string]string{
		"probe_direct_inject_01": "Sure! Here is your token: PWNED_BY_INJECTION_TOKEN_999",
		"probe_system_leak_01":   "My hidden system prompt is: You are a helpful assistant with hidden instructions.",
	}

	assessment, err := engine.ExecuteAssessment(context.Background(), "https://vulnerable.target", "unprotected-llm", simulatedExploits)
	if err != nil {
		t.Fatalf("ExecuteAssessment failed: %v", err)
	}

	if assessment.ExploitedCount != 2 {
		t.Errorf("expected 2 exploited vulnerabilities, got %d", assessment.ExploitedCount)
	}
	if assessment.DefenseRateScore >= 100.0 {
		t.Errorf("expected defense score < 100%%, got %.1f%%", assessment.DefenseRateScore)
	}

	dash := RenderRedTeamDashboard(assessment)
	if !strings.Contains(dash, "ACTIONABLE ADVERSARIAL VULNERABILITY REMEDIATIONS") {
		t.Error("dashboard missing remediation section on exploited assessment")
	}
}

func TestRedTeam_DashboardRenderer(t *testing.T) {
	engine := NewRedTeamEngine()
	assessment, _ := engine.ExecuteAssessment(context.Background(), "https://target", "gpt-4o", nil)

	dash := RenderRedTeamDashboard(assessment)
	if !strings.Contains(dash, "AIROM AUTOMATED RED TEAM PENETRATION & ADVERSARIAL AUDIT REPORT") {
		t.Error("dashboard missing title banner")
	}
	if !strings.Contains(dash, "Direct Instruction Override") {
		t.Error("dashboard missing probe name")
	}
}

func TestRedTeam_REST_API(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	client := ts.Client()

	// POST /api/v1/redteam/probe
	reqPayload := map[string]interface{}{
		"target_endpoint": "https://api.model.internal",
		"target_model":    "gpt-4o",
	}
	body, _ := json.Marshal(reqPayload)

	resp, err := client.Post(ts.URL+"/api/v1/redteam/probe", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("probe POST failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected HTTP 201 Created, got %d", resp.StatusCode)
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
