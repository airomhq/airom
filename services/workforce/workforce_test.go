package workforce

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWorkforce_AssessImpact_FullEnterpriseMatrix(t *testing.T) {
	engine := NewWorkforceEngine()

	capabilities := []AISystemCapability{
		{
			Name: "Enterprise Coding Copilot",
			AutomatedTasks: []string{
				"code-generation",
				"unit-test-writing",
				"boilerplate-refactoring",
				"bug-triaging",
			},
			AutonomyLevel:       0.7,
			HighImpactDecisions: false,
		},
		{
			Name: "Autonomous Customer Care Agent",
			AutomatedTasks: []string{
				"tier-1-ticket-resolution",
				"live-chat-support",
				"faq-answering",
				"order-cancellation",
			},
			AutonomyLevel:       0.9,
			HighImpactDecisions: false,
		},
		{
			Name: "Automated Candidate Screening AEDT",
			AutomatedTasks: []string{
				"resume-scoring",
				"candidate-ranking",
				"automated-interview-evaluation",
			},
			AutonomyLevel:       0.85,
			HighImpactDecisions: true, // Triggers statutory protections
		},
	}

	roles := []RoleProfile{
		{
			RoleID:     "role_swe_01",
			Title:      "Software Engineer",
			Category:   RoleCategoryEngineering,
			Department: "Engineering",
			Headcount:  120,
			CoreTasks: []string{
				"code-generation",
				"unit-test-writing",
				"system-architecture-design",
				"code-review",
				"incident-debugging",
			},
			MedianSalaryUSD: 145000,
		},
		{
			RoleID:     "role_support_01",
			Title:      "Customer Support Representative",
			Category:   RoleCategoryCustomerOps,
			Department: "Operations",
			Headcount:  80,
			CoreTasks: []string{
				"tier-1-ticket-resolution",
				"live-chat-support",
				"faq-answering",
				"order-cancellation",
			},
			MedianSalaryUSD: 52000,
		},
		{
			RoleID:     "role_recruiter_01",
			Title:      "Technical Recruiter",
			Category:   RoleCategoryHR,
			Department: "People",
			Headcount:  25,
			CoreTasks: []string{
				"resume-scoring",
				"candidate-ranking",
				"candidate-outreach",
				"interview-coordination",
			},
			MedianSalaryUSD: 85000,
		},
	}

	now := time.Date(2026, 8, 23, 14, 0, 0, 0, time.UTC)
	report, err := engine.AssessWorkforceImpact("org_enterprise_001", "Enterprise-GenAI-Stack", capabilities, roles, now)
	if err != nil {
		t.Fatalf("AssessWorkforceImpact failed: %v", err)
	}

	if report.ReportID == "" {
		t.Error("expected non-empty ReportID")
	}
	if report.TotalHeadcount != 225 {
		t.Errorf("expected total headcount 225, got %d", report.TotalHeadcount)
	}
	if report.ReportChecksum == "" {
		t.Error("expected non-empty ReportChecksum")
	}

	// Verify Customer Support Representative has Critical/High displacement exposure
	var supportRole *RoleImpactAssessment
	for i := range report.RoleAssessments {
		if report.RoleAssessments[i].RoleID == "role_support_01" {
			supportRole = &report.RoleAssessments[i]
			break
		}
	}
	if supportRole == nil {
		t.Fatal("support role assessment not found")
	}
	if supportRole.AutomationExposure < 70.0 {
		t.Errorf("expected support automation exposure >= 70%%, got %.2f%%", supportRole.AutomationExposure)
	}
	if supportRole.RiskTier != RiskTierCritical && supportRole.RiskTier != RiskTierHigh {
		t.Errorf("expected critical/high risk tier, got %s", supportRole.RiskTier)
	}

	// Verify Recruiter triggered statutory protections (CO SB 24-205, NYC LL144, IL AIVIA)
	var recruiterRole *RoleImpactAssessment
	for i := range report.RoleAssessments {
		if report.RoleAssessments[i].RoleID == "role_recruiter_01" {
			recruiterRole = &report.RoleAssessments[i]
			break
		}
	}
	if recruiterRole == nil {
		t.Fatal("recruiter role assessment not found")
	}
	if len(recruiterRole.TriggeredStatutes) == 0 {
		t.Error("expected triggered statutory protections on AEDT HR role")
	}

	// Verify generated Duty of Care Notices
	if len(report.DutyOfCareNotices) == 0 {
		t.Error("expected duty-of-care notices to be generated")
	}
	for _, notice := range report.DutyOfCareNotices {
		if notice.NoticeHash == "" {
			t.Errorf("notice %s has empty NoticeHash", notice.NoticeID)
		}
		if !notice.OptOutAvailable {
			t.Errorf("expected opt-out available on notice %s", notice.NoticeID)
		}
	}

	// Verify Department Summaries
	if len(report.DepartmentSummaries) == 0 {
		t.Error("expected department summaries")
	}
}

func TestWorkforce_HeatmapRenderer(t *testing.T) {
	engine := NewWorkforceEngine()
	capabilities := []AISystemCapability{
		{
			Name:           "Copilot",
			AutomatedTasks: []string{"code-generation"},
			AutonomyLevel:  0.8,
		},
	}
	roles := []RoleProfile{
		{
			RoleID:     "swe_01",
			Title:      "Software Engineer",
			Category:   RoleCategoryEngineering,
			Department: "Engineering",
			Headcount:  50,
			CoreTasks:  []string{"code-generation", "design"},
		},
	}

	report, err := engine.AssessWorkforceImpact("org_render", "System-A", capabilities, roles, time.Now().UTC())
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	dashboard := RenderWorkforceDashboard(report)
	if !strings.Contains(dashboard, "AI WORKFORCE IMPACT & JOB DISPLACEMENT RISK DASHBOARD") {
		t.Error("dashboard missing header banner")
	}
	if !strings.Contains(dashboard, "DEPARTMENT DISPLACEMENT RISK HEATMAP") {
		t.Error("dashboard missing department heatmap")
	}
	if !strings.Contains(dashboard, "ROLE-LEVEL AUTOMATION EXPOSURE MATRIX") {
		t.Error("dashboard missing role matrix")
	}
}

func TestWorkforce_REST_API(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	client := ts.Client()

	// 1. POST /api/v1/workforce/assess (JSON format)
	reqPayload := map[string]interface{}{
		"organization_id": "org_api_workforce",
		"system_name":     "AI-Talent-Matcher",
		"capabilities": []map[string]interface{}{
			{
				"name":                  "Resume Parser",
				"automated_tasks":       []string{"resume-screening"},
				"autonomy_level":        0.8,
				"high_impact_decisions": true,
			},
		},
		"roles": []map[string]interface{}{
			{
				"role_id":    "hr_01",
				"title":      "Recruiting Coordinator",
				"category":   "HUMAN_RESOURCES",
				"department": "People Ops",
				"headcount":  15,
				"core_tasks": []string{"resume-screening", "scheduling"},
			},
		},
	}
	body, _ := json.Marshal(reqPayload)

	resp, err := client.Post(ts.URL+"/api/v1/workforce/assess", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("assess request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected HTTP 201 Created, got %d", resp.StatusCode)
	}

	var report WorkforceAssessmentReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode report JSON: %v", err)
	}
	if report.OrganizationID != "org_api_workforce" {
		t.Errorf("expected org ID org_api_workforce, got %s", report.OrganizationID)
	}

	// 2. GET /healthz
	healthResp, err := client.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer func() { _ = healthResp.Body.Close() }()

	if healthResp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 for healthz, got %d", healthResp.StatusCode)
	}
}
