package compliancedb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAPI_Healthz(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("failed to GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	if data["status"] != "ok" || data["service"] != "airom-compliancedb" {
		t.Errorf("unexpected healthz response: %+v", data)
	}
}

func TestAPI_IngestSnapshotAndHistory(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	repoID := "repo-test-api"
	t0 := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)

	// 1. Ingest Snapshot 1 (with a gap)
	req1 := IngestionRequest{
		RepoID:               repoID,
		CommitSHA:            "commit-aaa",
		Branch:               "main",
		ScanTimestamp:        t0,
		AIBOMSHA256:          "sha-aaa",
		ComponentsCount:      15,
		VulnerabilitiesCount: 0,
		ControlsMet:          3,
		ControlsGap:          1,
		ControlsManual:       0,
		Evaluations: []ControlEvaluation{
			{ControlID: "co.ai-act.impact-assessment", StatuteRef: "CO SB 24-205", Verdict: VerdictGap, GapMessage: "Missing annual assessment"},
			{ControlID: "nyc.ll144.bias-audit", StatuteRef: "NYC LL144", Verdict: VerdictMet},
		},
	}

	body1, _ := json.Marshal(req1)
	postResp1, err := http.Post(fmt.Sprintf("%s/api/v1/repos/%s/snapshots", ts.URL, repoID), "application/json", bytes.NewReader(body1))
	if err != nil {
		t.Fatalf("failed to POST snapshot: %v", err)
	}
	defer func() { _ = postResp1.Body.Close() }()

	if postResp1.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", postResp1.StatusCode)
	}

	var ingResp1 IngestionResponse
	_ = json.NewDecoder(postResp1.Body).Decode(&ingResp1)
	if ingResp1.SelfHash == "" || ingResp1.ChainStatus != "VALID" || ingResp1.NewIncidentsCount != 1 {
		t.Errorf("unexpected ingestion response 1: %+v", ingResp1)
	}

	// 2. Ingest Snapshot 2 (Remediation 48h later)
	t1 := t0.Add(48 * time.Hour)
	req2 := IngestionRequest{
		RepoID:               repoID,
		CommitSHA:            "commit-bbb",
		Branch:               "main",
		ScanTimestamp:        t1,
		AIBOMSHA256:          "sha-bbb",
		ComponentsCount:      15,
		VulnerabilitiesCount: 0,
		ControlsMet:          4,
		ControlsGap:          0,
		ControlsManual:       0,
		Evaluations: []ControlEvaluation{
			{ControlID: "co.ai-act.impact-assessment", StatuteRef: "CO SB 24-205", Verdict: VerdictMet},
			{ControlID: "nyc.ll144.bias-audit", StatuteRef: "NYC LL144", Verdict: VerdictMet},
		},
	}

	body2, _ := json.Marshal(req2)
	postResp2, err := http.Post(fmt.Sprintf("%s/api/v1/repos/%s/snapshots", ts.URL, repoID), "application/json", bytes.NewReader(body2))
	if err != nil {
		t.Fatalf("failed to POST snapshot 2: %v", err)
	}
	defer func() { _ = postResp2.Body.Close() }()

	var ingResp2 IngestionResponse
	_ = json.NewDecoder(postResp2.Body).Decode(&ingResp2)
	if ingResp2.PrevHash != ingResp1.SelfHash || len(ingResp2.ResolvedIncidents) != 1 {
		t.Errorf("unexpected ingestion response 2: %+v", ingResp2)
	}

	// 3. Query Repo History
	histResp, err := http.Get(fmt.Sprintf("%s/api/v1/repos/%s/history", ts.URL, repoID))
	if err != nil {
		t.Fatalf("failed to GET history: %v", err)
	}
	defer func() { _ = histResp.Body.Close() }()

	var history RepoHistoryResponse
	_ = json.NewDecoder(histResp.Body).Decode(&history)
	if history.TotalCount != 2 || !history.ChainReport.Valid {
		t.Errorf("unexpected history response: %+v", history)
	}

	// 4. Query Repo Incidents
	incResp, err := http.Get(fmt.Sprintf("%s/api/v1/repos/%s/incidents", ts.URL, repoID))
	if err != nil {
		t.Fatalf("failed to GET incidents: %v", err)
	}
	defer func() { _ = incResp.Body.Close() }()

	var incs RepoIncidentsResponse
	_ = json.NewDecoder(incResp.Body).Decode(&incs)
	if incs.OpenCount != 0 || incs.Resolved != 1 {
		t.Errorf("unexpected incidents response: %+v", incs)
	}
	if incs.Incidents[0].ResolutionDurationHours == nil || *incs.Incidents[0].ResolutionDurationHours != 48.0 {
		t.Errorf("expected 48.0 resolution duration, got %v", incs.Incidents[0].ResolutionDurationHours)
	}
}

func TestAPI_OrgComplianceAggregation(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	orgID := "org-acme"
	svc.RegisterOrg(Organization{ID: orgID, Slug: "acme", Name: "Acme Corp"})
	svc.RegisterRepo(Repository{ID: "repo-1", OrgID: orgID, GitURL: "github.com/acme/app1"})
	svc.RegisterRepo(Repository{ID: "repo-2", OrgID: orgID, GitURL: "github.com/acme/app2"})

	t0 := time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)

	// Ingest for Repo 1 (CO AI Act: met)
	req1 := IngestionRequest{
		RepoID:         "repo-1",
		CommitSHA:      "c1",
		Branch:         "main",
		ScanTimestamp:  t0,
		AIBOMSHA256:    "sha1",
		ControlsMet:    2,
		ControlsGap:    0,
		ControlsManual: 1,
		Evaluations: []ControlEvaluation{
			{ControlID: "co.1", StatuteRef: "CO SB 24-205", Verdict: VerdictMet},
			{ControlID: "co.2", StatuteRef: "CO SB 24-205", Verdict: VerdictMet},
			{ControlID: "co.3", StatuteRef: "CO SB 24-205", Verdict: VerdictManual},
		},
	}
	b1, _ := json.Marshal(req1)
	if r1, err := http.Post(fmt.Sprintf("%s/api/v1/repos/repo-1/snapshots", ts.URL), "application/json", bytes.NewReader(b1)); err == nil && r1 != nil {
		_ = r1.Body.Close()
	}

	// Ingest for Repo 2 (NYC LL144: gap)
	req2 := IngestionRequest{
		RepoID:         "repo-2",
		CommitSHA:      "c2",
		Branch:         "main",
		ScanTimestamp:  t0,
		AIBOMSHA256:    "sha2",
		ControlsMet:    1,
		ControlsGap:    1,
		ControlsManual: 0,
		Evaluations: []ControlEvaluation{
			{ControlID: "nyc.1", StatuteRef: "NYC LL144", Verdict: VerdictMet},
			{ControlID: "nyc.2", StatuteRef: "NYC LL144", Verdict: VerdictGap},
		},
	}
	b2, _ := json.Marshal(req2)
	if r2, err := http.Post(fmt.Sprintf("%s/api/v1/repos/repo-2/snapshots", ts.URL), "application/json", bytes.NewReader(b2)); err == nil && r2 != nil {
		_ = r2.Body.Close()
	}

	// Query Org Compliance aggregation
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/orgs/%s/compliance", ts.URL, orgID))
	if err != nil {
		t.Fatalf("failed to GET org compliance: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var orgComp OrgComplianceResponse
	_ = json.NewDecoder(resp.Body).Decode(&orgComp)

	if orgComp.TotalRepos != 2 {
		t.Errorf("expected 2 total repos, got %d", orgComp.TotalRepos)
	}
	if orgComp.TotalMet != 3 || orgComp.TotalGaps != 1 || orgComp.TotalManual != 1 {
		t.Errorf("unexpected aggregated totals: met=%d, gap=%d, manual=%d", orgComp.TotalMet, orgComp.TotalGaps, orgComp.TotalManual)
	}
	if len(orgComp.Regulations) != 2 {
		t.Errorf("expected 2 regulations aggregated, got %d", len(orgComp.Regulations))
	}
}

func TestAPI_ErrorHandling(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	// 1. Malformed JSON
	resp1, _ := http.Post(ts.URL+"/api/v1/repos/r1/snapshots", "application/json", bytes.NewReader([]byte("{malformed: true")))
	if resp1 != nil {
		if resp1.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request on malformed json, got %d", resp1.StatusCode)
		}
		_ = resp1.Body.Close()
	}

	// 2. Missing Commit SHA
	req := IngestionRequest{RepoID: "r1"}
	b, _ := json.Marshal(req)
	resp2, _ := http.Post(ts.URL+"/api/v1/repos/r1/snapshots", "application/json", bytes.NewReader(b))
	if resp2 != nil {
		if resp2.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request on missing commit, got %d", resp2.StatusCode)
		}
		_ = resp2.Body.Close()
	}

	// 3. Not Found Route
	resp3, _ := http.Get(ts.URL + "/api/v1/unknown/endpoint")
	if resp3 != nil {
		if resp3.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 on unknown route, got %d", resp3.StatusCode)
		}
		_ = resp3.Body.Close()
	}

	// 4. Method Not Allowed
	resp4, _ := http.Post(ts.URL+"/healthz", "application/json", nil)
	if resp4 != nil {
		if resp4.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 on POST /healthz, got %d", resp4.StatusCode)
		}
		_ = resp4.Body.Close()
	}
}

func BenchmarkAPI_IngestSnapshot(b *testing.B) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	t0 := time.Now().UTC()
	req := IngestionRequest{
		RepoID:         "repo-bench",
		CommitSHA:      "c-bench",
		Branch:         "main",
		ScanTimestamp:  t0,
		AIBOMSHA256:    "sha-bench",
		ControlsMet:    5,
		ControlsGap:    0,
		ControlsManual: 0,
	}
	body, _ := json.Marshal(req)
	client := ts.Client()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, _ := client.Post(ts.URL+"/api/v1/repos/repo-bench/snapshots", "application/json", bytes.NewReader(body))
		if resp != nil {
			_ = resp.Body.Close()
		}
	}
}

func BenchmarkAPI_OrgCompliance(b *testing.B) {
	svc := NewService()
	svc.RegisterOrg(Organization{ID: "bench-org", Name: "Bench Org"})
	svc.RegisterRepo(Repository{ID: "bench-repo", OrgID: "bench-org"})
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	client := ts.Client()
	url := ts.URL + "/api/v1/orgs/bench-org/compliance"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, _ := client.Get(url)
		if resp != nil {
			_ = resp.Body.Close()
		}
	}
}
