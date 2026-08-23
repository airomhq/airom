package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDashboard_CalculateExecutivePosture_MultiOrg(t *testing.T) {
	engine := NewDashboardEngine()

	orgs := []OrganizationRollup{
		{
			OrganizationID:     "org_fintech",
			OrganizationName:   "Global Fintech Subsidiary",
			Sector:             "Financial Services",
			RepositoryCount:    45,
			TotalComponents:    320,
			ComplianceScore:    96.5,
			CriticalGapsCount:  0,
			ShadowAICount:      1,
			DisplacedFTECount:  12.5,
			UrgentFilingsCount: 0,
			FrameworkCompliance: map[string]float64{
				"Colorado AI Act": 98.0,
				"EU AI Act":       95.0,
				"NYC LL144":       96.5,
			},
			LastAuditedAt: time.Now().UTC(),
		},
		{
			OrganizationID:     "org_health",
			OrganizationName:   "Healthcare Cloud Unit",
			Sector:             "Healthcare",
			RepositoryCount:    30,
			TotalComponents:    180,
			ComplianceScore:    72.0,
			CriticalGapsCount:  4,
			ShadowAICount:      6,
			DisplacedFTECount:  5.0,
			UrgentFilingsCount: 2,
			FrameworkCompliance: map[string]float64{
				"Colorado AI Act": 70.0,
				"EU AI Act":       74.0,
			},
			LastAuditedAt: time.Now().UTC(),
		},
	}

	matrix, err := engine.CalculateExecutivePosture(orgs)
	if err != nil {
		t.Fatalf("CalculateExecutivePosture failed: %v", err)
	}

	if matrix.MatrixID == "" {
		t.Error("expected non-empty MatrixID")
	}
	if matrix.Summary.TotalOrganizations != 2 {
		t.Errorf("expected 2 orgs, got %d", matrix.Summary.TotalOrganizations)
	}
	if matrix.Summary.TotalCriticalGaps != 4 {
		t.Errorf("expected 4 critical gaps, got %d", matrix.Summary.TotalCriticalGaps)
	}
	if matrix.MatrixChecksum == "" {
		t.Error("expected non-empty MatrixChecksum")
	}

	// Verify Fintech subsidiary received Grade A+
	var fintechOrg *OrganizationRollup
	for i := range matrix.Organizations {
		if matrix.Organizations[i].OrganizationID == "org_fintech" {
			fintechOrg = &matrix.Organizations[i]
			break
		}
	}
	if fintechOrg == nil || fintechOrg.PostureGrade != GradeAPlus {
		t.Errorf("expected Grade A+ for fintech org, got %v", fintechOrg)
	}
}

func TestDashboard_RenderExecutiveDashboard(t *testing.T) {
	engine := NewDashboardEngine()
	orgs := []OrganizationRollup{
		{
			OrganizationID:   "org_render",
			OrganizationName: "Render Corp",
			Sector:           "Technology",
			RepositoryCount:  10,
			TotalComponents:  50,
			ComplianceScore:  91.0,
			FrameworkCompliance: map[string]float64{
				"Colorado AI Act": 91.0,
			},
		},
	}

	matrix, _ := engine.CalculateExecutivePosture(orgs)
	dash := RenderExecutiveDashboard(matrix)

	if !strings.Contains(dash, "AIROM ENTERPRISE COMPLIANCE & AI GOVERNANCE EXECUTIVE DASHBOARD") {
		t.Error("dashboard missing title banner")
	}
	if !strings.Contains(dash, "Render Corp") {
		t.Error("dashboard missing organization row")
	}
}

func TestDashboard_REST_API(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	client := ts.Client()

	reqPayload := map[string]interface{}{
		"organizations": []map[string]interface{}{
			{
				"organization_id":   "org_api",
				"organization_name": "API Corp",
				"compliance_score":  95.0,
			},
		},
	}
	body, _ := json.Marshal(reqPayload)

	resp, err := client.Post(ts.URL+"/api/v1/dashboard/posture", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("posture POST failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected HTTP 201 Created, got %d", resp.StatusCode)
	}

	// GET /api/v1/dashboard/posture
	getResp, err := client.Get(ts.URL + "/api/v1/dashboard/posture")
	if err != nil {
		t.Fatalf("posture GET failed: %v", err)
	}
	defer func() { _ = getResp.Body.Close() }()

	if getResp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 for GET posture, got %d", getResp.StatusCode)
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
