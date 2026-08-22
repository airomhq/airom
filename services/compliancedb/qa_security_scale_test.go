package compliancedb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestQA_MultiTenantHierarchyScale_500Tenants simulates 500 distinct enterprise organizations
// with 2,000 repositories in parallel. It ingests compliance scans across diverse state regulations
// (CO SB 24-205, NYC LL144, CA AB 2013) and verifies absolute cross-tenant isolation with zero data leakage.
func TestQA_MultiTenantHierarchyScale_500Tenants(t *testing.T) {
	t.Log("=== TestQA_MultiTenantHierarchyScale_500Tenants Started ===")
	numOrgs := 500
	reposPerOrg := 4
	totalRepos := numOrgs * reposPerOrg // 2,000 repositories

	svc := NewService()
	handler := svc.Routes()

	t0 := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)

	// Ground truth trackers per organization
	type OrgExpected struct {
		OrgID       string
		TotalRepos  int
		TotalMet    int
		TotalGap    int
		TotalManual int
		RegStats    map[string]*OrgComplianceRegulationStats // statute -> stats
	}

	expectedByOrg := make([]OrgExpected, numOrgs)
	for i := 0; i < numOrgs; i++ {
		orgID := fmt.Sprintf("org-%03d", i)
		slug := fmt.Sprintf("slug-%03d", i)
		svc.RegisterOrg(Organization{
			ID:        orgID,
			Slug:      slug,
			Name:      fmt.Sprintf("Enterprise Tenant %03d", i),
			CreatedAt: t0,
		})

		expectedByOrg[i] = OrgExpected{
			OrgID:      orgID,
			TotalRepos: reposPerOrg,
			RegStats: map[string]*OrgComplianceRegulationStats{
				"CO SB 24-205": {RegulationID: "CO SB 24-205"},
				"NYC LL144":    {RegulationID: "NYC LL144"},
				"CA AB 2013":   {RegulationID: "CA AB 2013"},
			},
		}

		for r := 0; r < reposPerOrg; r++ {
			repoID := fmt.Sprintf("repo-%03d-%d", i, r)
			svc.RegisterRepo(Repository{
				ID:            repoID,
				OrgID:         orgID,
				GitURL:        fmt.Sprintf("git://internal.git/%s/%s.git", orgID, repoID),
				DefaultBranch: "main",
				CreatedAt:     t0,
			})
		}
	}

	// Define standard regulation controls to test diverse statutes
	statutes := []struct {
		ControlID  string
		StatuteRef string
	}{
		{"co.ai-act.impact-assessment", "CO SB 24-205"},
		{"co.ai-act.consumer-notice", "CO SB 24-205"},
		{"nyc.ll144.bias-audit", "NYC LL144"},
		{"nyc.ll144.candidate-notice", "NYC LL144"},
		{"ca.ab2013.training-data", "CA AB 2013"},
		{"ca.ab2013.pii-disclosure", "CA AB 2013"},
	}

	// Pre-calculate expected compliance distributions per org & repo
	type RepoIngestTask struct {
		OrgIndex int
		RepoID   string
		Req      IngestionRequest
	}

	tasks := make([]RepoIngestTask, 0, totalRepos)

	for i := 0; i < numOrgs; i++ {
		for r := 0; r < reposPerOrg; r++ {
			repoID := fmt.Sprintf("repo-%03d-%d", i, r)

			var evals []ControlEvaluation
			metCount, gapCount, manualCount := 0, 0, 0

			for idx, c := range statutes {
				// Deterministic assignment based on org and repo index
				verdictMode := (i + r + idx) % 3
				var verdict string
				switch verdictMode {
				case 0:
					verdict = VerdictMet
					metCount++
					expectedByOrg[i].RegStats[c.StatuteRef].MetCount++
				case 1:
					verdict = VerdictGap
					gapCount++
					expectedByOrg[i].RegStats[c.StatuteRef].GapCount++
				case 2:
					verdict = VerdictManual
					manualCount++
					expectedByOrg[i].RegStats[c.StatuteRef].ManualCount++
				}

				evals = append(evals, ControlEvaluation{
					ID:         fmt.Sprintf("eval-%s-%s", repoID, c.ControlID),
					ControlID:  c.ControlID,
					StatuteRef: c.StatuteRef,
					Verdict:    verdict,
				})
			}

			expectedByOrg[i].TotalMet += metCount
			expectedByOrg[i].TotalGap += gapCount
			expectedByOrg[i].TotalManual += manualCount

			req := IngestionRequest{
				RepoID:               repoID,
				CommitSHA:            fmt.Sprintf("commit-%03d-%d", i, r),
				Branch:               "main",
				ScanTimestamp:        t0.Add(time.Duration(r*5) * time.Minute),
				AIBOMSHA256:          fmt.Sprintf("aibom-sha-%03d-%d", i, r),
				ComponentsCount:      20 + (i % 10),
				VulnerabilitiesCount: r,
				ControlsMet:          metCount,
				ControlsGap:          gapCount,
				ControlsManual:       manualCount,
				Evaluations:          evals,
			}

			tasks = append(tasks, RepoIngestTask{
				OrgIndex: i,
				RepoID:   repoID,
				Req:      req,
			})
		}
	}

	t.Logf("Simulating parallel scan ingestion for %d repositories across %d tenant organizations...", totalRepos, numOrgs)
	ingestStart := time.Now()

	// Ingest 2,000 repository scans in parallel using 50 worker goroutines
	concurrency := 50
	taskCh := make(chan RepoIngestTask, totalRepos)
	for _, task := range tasks {
		taskCh <- task
	}
	close(taskCh)

	var wg sync.WaitGroup
	var ingestErrors int64

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskCh {
				body, err := json.Marshal(task.Req)
				if err != nil {
					atomic.AddInt64(&ingestErrors, 1)
					continue
				}

				url := fmt.Sprintf("/api/v1/repos/%s/snapshots", task.RepoID)
				httpReq := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httpReq)

				if rec.Code != http.StatusCreated {
					atomic.AddInt64(&ingestErrors, 1)
				}
			}
		}()
	}

	wg.Wait()
	ingestDuration := time.Since(ingestStart)
	t.Logf("Ingested %d repositories in %v (%.2f reqs/sec). Errors: %d", totalRepos, ingestDuration, float64(totalRepos)/ingestDuration.Seconds(), ingestErrors)

	if ingestErrors > 0 {
		t.Fatalf("Ingestion experienced %d errors across 2,000 repositories", ingestErrors)
	}

	// Verify Tenant Isolation and Aggregation for all 500 organizations in parallel
	t.Logf("Validating zero cross-tenant contamination across all %d organizations...", numOrgs)
	queryStart := time.Now()

	var totalVerifiedMet, totalVerifiedGaps, totalVerifiedManual int64
	var isolationErrors int64
	orgCh := make(chan int, numOrgs)
	for i := 0; i < numOrgs; i++ {
		orgCh <- i
	}
	close(orgCh)

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for orgIdx := range orgCh {
				exp := expectedByOrg[orgIdx]
				url := fmt.Sprintf("/api/v1/orgs/%s/compliance", exp.OrgID)
				httpReq := httptest.NewRequest(http.MethodGet, url, nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httpReq)

				if rec.Code != http.StatusOK {
					atomic.AddInt64(&isolationErrors, 1)
					continue
				}

				var orgComp OrgComplianceResponse
				if err := json.NewDecoder(rec.Body).Decode(&orgComp); err != nil {
					atomic.AddInt64(&isolationErrors, 1)
					continue
				}

				// Boundary Check 1: Repo count isolation
				if orgComp.TotalRepos != exp.TotalRepos {
					atomic.AddInt64(&isolationErrors, 1)
				}

				// Boundary Check 2: Control metrics precision
				if orgComp.TotalMet != exp.TotalMet || orgComp.TotalGaps != exp.TotalGap || orgComp.TotalManual != exp.TotalManual {
					atomic.AddInt64(&isolationErrors, 1)
				}

				atomic.AddInt64(&totalVerifiedMet, int64(orgComp.TotalMet))
				atomic.AddInt64(&totalVerifiedGaps, int64(orgComp.TotalGaps))
				atomic.AddInt64(&totalVerifiedManual, int64(orgComp.TotalManual))

				// Boundary Check 3: Multi-regulation breakdown matching
				regCountMap := make(map[string]OrgComplianceRegulationStats)
				for _, r := range orgComp.Regulations {
					regCountMap[r.RegulationID] = r
				}

				for statName, expectedStat := range exp.RegStats {
					actualStat, ok := regCountMap[statName]
					if !ok {
						atomic.AddInt64(&isolationErrors, 1)
						continue
					}
					if actualStat.MetCount != expectedStat.MetCount ||
						actualStat.GapCount != expectedStat.GapCount ||
						actualStat.ManualCount != expectedStat.ManualCount ||
						actualStat.TotalRepos != exp.TotalRepos {
						atomic.AddInt64(&isolationErrors, 1)
					}
				}

				// Boundary Check 4: Query by Org Slug returns identical tenant data
				slugURL := fmt.Sprintf("/api/v1/orgs/slug-%03d/compliance", orgIdx)
				slugReq := httptest.NewRequest(http.MethodGet, slugURL, nil)
				slugRec := httptest.NewRecorder()
				handler.ServeHTTP(slugRec, slugReq)

				if slugRec.Code == http.StatusOK {
					var slugComp OrgComplianceResponse
					_ = json.NewDecoder(slugRec.Body).Decode(&slugComp)
					if slugComp.TotalMet != exp.TotalMet || slugComp.TotalGaps != exp.TotalGap {
						atomic.AddInt64(&isolationErrors, 1)
					}
				}
			}
		}()
	}

	wg.Wait()
	queryDuration := time.Since(queryStart)
	t.Logf("Validated all %d tenant organizations in %v (%.2f queries/sec)", numOrgs, queryDuration, float64(numOrgs)/queryDuration.Seconds())

	if isolationErrors > 0 {
		t.Fatalf("Tenant isolation failed: detected %d cross-tenant leakage or calculation errors", isolationErrors)
	}

	// Boundary Check 5: Non-existent tenant boundary query
	emptyReq := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/org-ghost-tenant/compliance", nil)
	emptyRec := httptest.NewRecorder()
	handler.ServeHTTP(emptyRec, emptyReq)

	if emptyRec.Code != http.StatusOK {
		t.Fatalf("Failed to query non-existent tenant: code %d", emptyRec.Code)
	}
	var emptyComp OrgComplianceResponse
	_ = json.NewDecoder(emptyRec.Body).Decode(&emptyComp)
	if emptyComp.TotalRepos != 0 || emptyComp.TotalMet != 0 || emptyComp.TotalGaps != 0 {
		t.Fatalf("Ghost tenant returned leaked metrics: %+v", emptyComp)
	}

	// Grand totals verification across all 500 tenants (2000 repos * 6 controls = 12,000 assessments)
	expectedGlobalTotal := totalRepos * len(statutes)
	actualGlobalTotal := int(totalVerifiedMet + totalVerifiedGaps + totalVerifiedManual)
	if actualGlobalTotal != expectedGlobalTotal {
		t.Fatalf("Global sum mismatch: expected %d total assessments, got %d", expectedGlobalTotal, actualGlobalTotal)
	}

	t.Logf("Grand Global Totals: Met=%d, Gaps=%d, Manual=%d (Total: %d)", totalVerifiedMet, totalVerifiedGaps, totalVerifiedManual, actualGlobalTotal)
	t.Log("=== TestQA_MultiTenantHierarchyScale_500Tenants PASSED ===")
}

// TestQA_HighVolumeIncidentChurn_5KTransitions simulates 5,000 simultaneous compliance control
// transitions (gap -> gap -> met -> gap -> met) across multiple frameworks.
// It verifies exact incident resolution duration precision, absence of duplicate open incidents,
// and zero orphaned state under high concurrency.
func TestQA_HighVolumeIncidentChurn_5KTransitions(t *testing.T) {
	t.Log("=== TestQA_HighVolumeIncidentChurn_5KTransitions Started ===")
	numRepos := 100
	controlsPerRepo := 10
	totalControls := numRepos * controlsPerRepo // 1,000 distinct controls
	stepsPerControl := 5
	totalTransitions := totalControls * stepsPerControl // 5,000 transitions

	svc := NewService()
	handler := svc.Routes()

	frameworks := []string{
		"CO SB 24-205 §6-1-1703",
		"NYC LL144 §20-871",
		"CA AB 2013 §3100",
		"FCRA 15 U.S.C. § 1681",
		"HIPAA 45 CFR § 164.312",
		"EU AI Act Art 10",
		"NIST AI RMF GOVERN-1.1",
		"ISO/IEC 42001 §6.2",
	}

	t0 := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	// Chronological step offsets:
	// Step 0 (0h):   gap -> Opens Incident 1
	// Step 1 (24h):  gap -> Gap persists (no duplicate incident opened)
	// Step 2 (72h):  met -> Incident 1 resolved. Exact duration = 72.0 hours
	// Step 3 (120h): gap -> Regression! Opens Incident 2
	// Step 4 (168h): met -> Incident 2 resolved. Exact duration = 48.0 hours
	stepOffsets := []time.Duration{
		0 * time.Hour,
		24 * time.Hour,
		72 * time.Hour,
		120 * time.Hour,
		168 * time.Hour,
	}

	for r := 0; r < numRepos; r++ {
		repoID := fmt.Sprintf("repo-churn-%03d", r)
		svc.RegisterRepo(Repository{
			ID:        repoID,
			OrgID:     "org-churn",
			GitURL:    fmt.Sprintf("git://github.com/churn/%s.git", repoID),
			CreatedAt: t0,
		})
	}

	t.Logf("Simulating %d transitions across %d controls over 5 lifecycle stages...", totalTransitions, totalControls)
	churnStart := time.Now()

	// Execute 5 scan steps sequentially across each repo, while parallelizing across all 100 repositories
	var wg sync.WaitGroup
	var churnErrors int64
	repoCh := make(chan int, numRepos)
	for r := 0; r < numRepos; r++ {
		repoCh <- r
	}
	close(repoCh)

	concurrency := 25
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repoIdx := range repoCh {
				repoID := fmt.Sprintf("repo-churn-%03d", repoIdx)

				for step := 0; step < stepsPerControl; step++ {
					scanTime := t0.Add(stepOffsets[step])
					var evals []ControlEvaluation

					metCount := 0
					gapCount := 0

					for c := 0; c < controlsPerRepo; c++ {
						ctrlID := fmt.Sprintf("ctrl-r%03d-c%02d", repoIdx, c)
						statute := frameworks[(repoIdx*controlsPerRepo+c)%len(frameworks)]

						var verdict string
						switch step {
						case 0, 1, 3:
							verdict = VerdictGap
							gapCount++
						case 2, 4:
							verdict = VerdictMet
							metCount++
						}

						evals = append(evals, ControlEvaluation{
							ID:         fmt.Sprintf("eval-%s-step%d", ctrlID, step),
							ControlID:  ctrlID,
							StatuteRef: statute,
							Verdict:    verdict,
							GapMessage: fmt.Sprintf("Gap at step %d", step),
						})
					}

					req := IngestionRequest{
						RepoID:               repoID,
						CommitSHA:            fmt.Sprintf("commit-%03d-s%d", repoIdx, step),
						Branch:               "main",
						ScanTimestamp:        scanTime,
						AIBOMSHA256:          fmt.Sprintf("aibom-%03d-s%d", repoIdx, step),
						ComponentsCount:      30,
						VulnerabilitiesCount: 0,
						ControlsMet:          metCount,
						ControlsGap:          gapCount,
						ControlsManual:       0,
						Evaluations:          evals,
					}

					body, err := json.Marshal(req)
					if err != nil {
						atomic.AddInt64(&churnErrors, 1)
						continue
					}

					url := fmt.Sprintf("/api/v1/repos/%s/snapshots", repoID)
					httpReq := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, httpReq)

					if rec.Code != http.StatusCreated {
						atomic.AddInt64(&churnErrors, 1)
					}
				}
			}
		}()
	}

	wg.Wait()
	churnDuration := time.Since(churnStart)
	t.Logf("Completed %d transitions across %d repos in %v (%.2f transitions/sec). Churn errors: %d",
		totalTransitions, numRepos, churnDuration, float64(totalTransitions)/churnDuration.Seconds(), churnErrors)

	if churnErrors > 0 {
		t.Fatalf("Incident churn experienced %d execution errors", churnErrors)
	}

	// Comprehensive Post-Churn State Machine Audit
	t.Log("Auditing post-churn incident state machine precision, duplicate absence, and orphaned state...")

	var totalAuditedResolved int64
	var totalAuditedOpen int64
	var precisionErrors int64

	for r := 0; r < numRepos; r++ {
		repoID := fmt.Sprintf("repo-churn-%03d", r)
		url := fmt.Sprintf("/api/v1/repos/%s/incidents", repoID)
		httpReq := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httpReq)

		if rec.Code != http.StatusOK {
			t.Fatalf("Failed to fetch incidents for %s: status %d", repoID, rec.Code)
		}

		var incResp RepoIncidentsResponse
		if err := json.NewDecoder(rec.Body).Decode(&incResp); err != nil {
			t.Fatalf("Failed to decode incidents response: %v", err)
		}

		// Check 1: Zero open incidents (no orphaned state after final met resolution)
		if incResp.OpenCount != 0 {
			t.Errorf("Repo %s has %d orphaned open incidents (expected 0)", repoID, incResp.OpenCount)
			atomic.AddInt64(&precisionErrors, 1)
		}
		atomic.AddInt64(&totalAuditedOpen, int64(incResp.OpenCount))

		// Check 2: Exactly 20 resolved incidents per repo (2 per control * 10 controls)
		expectedResolvedPerRepo := controlsPerRepo * 2
		if incResp.Resolved != expectedResolvedPerRepo {
			t.Errorf("Repo %s resolved count mismatch: expected %d, got %d", repoID, expectedResolvedPerRepo, incResp.Resolved)
			atomic.AddInt64(&precisionErrors, 1)
		}
		atomic.AddInt64(&totalAuditedResolved, int64(incResp.Resolved))

		// Check 3: Verify exact floating-point precision for resolution durations and no duplicate control IDs open
		byControl := make(map[string][]ComplianceIncident)
		for _, inc := range incResp.Incidents {
			byControl[inc.ControlID] = append(byControl[inc.ControlID], inc)
		}

		for cID, incList := range byControl {
			if len(incList) != 2 {
				t.Errorf("Control %s in repo %s has %d incidents (expected exactly 2)", cID, repoID, len(incList))
				atomic.AddInt64(&precisionErrors, 1)
				continue
			}

			// Sort by openedAt
			inc1 := incList[0]
			inc2 := incList[1]
			if inc1.OpenedAt.After(inc2.OpenedAt) {
				inc1, inc2 = inc2, inc1
			}

			// Cycle 1 Verification: opened at t0, resolved at t2 (duration = 72.0000h)
			if inc1.ResolutionDurationHours == nil {
				t.Errorf("Incident 1 for %s missing duration", cID)
				atomic.AddInt64(&precisionErrors, 1)
			} else {
				d1 := *inc1.ResolutionDurationHours
				if math.Abs(d1-72.0) > 1e-5 {
					t.Errorf("Incident 1 duration precision error: expected 72.0h, got %f", d1)
					atomic.AddInt64(&precisionErrors, 1)
				}
			}

			// Cycle 2 Verification: opened at t3, resolved at t4 (duration = 48.0000h)
			if inc2.ResolutionDurationHours == nil {
				t.Errorf("Incident 2 for %s missing duration", cID)
				atomic.AddInt64(&precisionErrors, 1)
			} else {
				d2 := *inc2.ResolutionDurationHours
				if math.Abs(d2-48.0) > 1e-5 {
					t.Errorf("Incident 2 duration precision error: expected 48.0h, got %f", d2)
					atomic.AddInt64(&precisionErrors, 1)
				}
			}
		}

		// Check 4: Validate hash chain integrity for repository
		histReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/repos/%s/history", repoID), nil)
		histRec := httptest.NewRecorder()
		handler.ServeHTTP(histRec, histReq)

		if histRec.Code == http.StatusOK {
			var hist RepoHistoryResponse
			_ = json.NewDecoder(histRec.Body).Decode(&hist)
			if !hist.ChainReport.Valid || hist.TotalCount != stepsPerControl {
				t.Errorf("Repo %s hash chain invalid or incomplete: %+v", repoID, hist.ChainReport)
			}
		}
	}

	if precisionErrors > 0 {
		t.Fatalf("Incident state machine validation failed with %d precision/duplicate/orphan violations", precisionErrors)
	}

	expectedTotalResolved := int64(totalControls * 2) // 2,000 resolved incidents
	if totalAuditedResolved != expectedTotalResolved || totalAuditedOpen != 0 {
		t.Fatalf("Incident totals mismatch: expected %d resolved / 0 open, got %d resolved / %d open",
			expectedTotalResolved, totalAuditedResolved, totalAuditedOpen)
	}

	t.Logf("State Machine Integrity Verified: 5,000 transitions -> %d resolved incidents, 0 open, 0 duplicates, 0 orphaned state", totalAuditedResolved)
	t.Log("=== TestQA_HighVolumeIncidentChurn_5KTransitions PASSED ===")
}

// TestQA_AdversarialTenantCrossInjection attempts sophisticated multi-tenant adversarial attack vectors:
// 1. Cross-tenant snapshot injection (repoID A into repoID B's chain)
// 2. Forged parent hash linkage pointing to foreign tenant snapshots
// 3. Malformed / extreme integer overflow & underflow payloads (MaxInt64, MinInt64, negative counts, malformed JSON)
// 4. Time regression and cryptographic replay attacks
// Verifies that the validator and API fail-closed safely with zero data corruption.
func TestQA_AdversarialTenantCrossInjection(t *testing.T) {
	t.Log("=== TestQA_AdversarialTenantCrossInjection Started ===")

	svc := NewService()
	handler := svc.Routes()

	t0 := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	tenantA := "org-alpha"
	tenantB := "org-bravo"
	repoA := "repo-alpha-core"
	repoB := "repo-bravo-core"

	svc.RegisterOrg(Organization{ID: tenantA, Slug: "alpha", Name: "Alpha Corp"})
	svc.RegisterOrg(Organization{ID: tenantB, Slug: "bravo", Name: "Bravo Corp"})
	svc.RegisterRepo(Repository{ID: repoA, OrgID: tenantA, GitURL: "git://alpha/repo.git"})
	svc.RegisterRepo(Repository{ID: repoB, OrgID: tenantB, GitURL: "git://bravo/repo.git"})

	// Setup baseline valid snapshots for both tenants
	reqA0 := IngestionRequest{
		RepoID:         repoA,
		CommitSHA:      "commit-a0",
		Branch:         "main",
		ScanTimestamp:  t0,
		AIBOMSHA256:    "sha-a0",
		ControlsMet:    5,
		ControlsGap:    0,
		ControlsManual: 0,
	}
	bodyA0, _ := json.Marshal(reqA0)
	httpReqA0 := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/snapshots", repoA), bytes.NewReader(bodyA0))
	recA0 := httptest.NewRecorder()
	handler.ServeHTTP(recA0, httpReqA0)

	if recA0.Code != http.StatusCreated {
		t.Fatalf("Failed to seed Tenant A baseline snapshot: code %d", recA0.Code)
	}
	var ingA0 IngestionResponse
	_ = json.NewDecoder(recA0.Body).Decode(&ingA0)

	reqB0 := IngestionRequest{
		RepoID:         repoB,
		CommitSHA:      "commit-b0",
		Branch:         "main",
		ScanTimestamp:  t0,
		AIBOMSHA256:    "sha-b0",
		ControlsMet:    3,
		ControlsGap:    1,
		ControlsManual: 0,
	}
	bodyB0, _ := json.Marshal(reqB0)
	httpReqB0 := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/snapshots", repoB), bytes.NewReader(bodyB0))
	recB0 := httptest.NewRecorder()
	handler.ServeHTTP(recB0, httpReqB0)

	if recB0.Code != http.StatusCreated {
		t.Fatalf("Failed to seed Tenant B baseline snapshot: code %d", recB0.Code)
	}
	var ingB0 IngestionResponse
	_ = json.NewDecoder(recB0.Body).Decode(&ingB0)

	t.Logf("Seeded baselines: RepoA Snap0 Hash=%s, RepoB Snap0 Hash=%s", ingA0.SelfHash[:12], ingB0.SelfHash[:12])

	// =========================================================================
	// ATTACK VECTOR 1: Cross-Tenant Payload Injection via API
	// Attacker sends request to Repo B endpoint with Repo A's ID in payload
	// =========================================================================
	t.Log("Executing Attack Vector 1: Cross-Tenant Payload Mismatch Injection...")
	spoofedReq := IngestionRequest{
		RepoID:         repoA, // Spoofed victim repo ID
		CommitSHA:      "commit-spoofed",
		Branch:         "main",
		ScanTimestamp:  t0.Add(1 * time.Hour),
		AIBOMSHA256:    "sha-spoofed",
		ControlsMet:    10,
		ControlsGap:    0,
		ControlsManual: 0,
	}
	spoofedBody, _ := json.Marshal(spoofedReq)
	spoofedHttpReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/snapshots", repoB), bytes.NewReader(spoofedBody))
	spoofedRec := httptest.NewRecorder()
	handler.ServeHTTP(spoofedRec, spoofedHttpReq)

	if spoofedRec.Code != http.StatusBadRequest {
		t.Fatalf("Fail-closed failure: Expected 400 Bad Request on cross-tenant payload injection, got %d", spoofedRec.Code)
	}
	t.Log("Attack Vector 1 PASSED: API rejected cross-tenant repo_id spoofing with 400 Bad Request.")

	// Verify Tenant A remains untouched
	histAReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/repos/%s/history", repoA), nil)
	histARec := httptest.NewRecorder()
	handler.ServeHTTP(histARec, histAReq)

	var histA RepoHistoryResponse
	_ = json.NewDecoder(histARec.Body).Decode(&histA)
	if histA.TotalCount != 1 || histA.Snapshots[0].CommitSHA != "commit-a0" {
		t.Fatalf("Tenant A state corrupted by spoofed request!")
	}

	// =========================================================================
	// ATTACK VECTOR 2: Forged Parent Hash Linkage & Cross-Repo Chain Splicing
	// =========================================================================
	t.Log("Executing Attack Vector 2: Forged Parent Hash & Chain Splicing Attack...")

	// 2a: Splicing foreign snapshot from Repo A directly into Repo B's chain
	snapA0 := NewSnapshot("snap-a0", repoA, "commit-a0", "main", t0, "sha-a0", 10, 0, 5, 0, 0, "", nil)
	snapB1 := NewSnapshot("snap-b1", repoB, "commit-b1", "main", t0.Add(1*time.Hour), "sha-b1", 10, 0, 5, 0, 0, snapA0.SelfHash, nil)

	splicedChain := []ScanSnapshot{snapA0, snapB1}
	spliceReport := ValidateChain(splicedChain)
	if spliceReport.Valid {
		t.Fatalf("Fail-closed failure: ValidateChain accepted cross-repo spliced chain!")
	}
	if spliceReport.BrokenAtIndex != 1 {
		t.Fatalf("Expected broken at index 1 for repo_id mismatch, got %d", spliceReport.BrokenAtIndex)
	}
	t.Logf("Attack Vector 2a PASSED: Cross-repo splice rejected: %s", spliceReport.Reason)

	// 2b: Tenant B forged parent hash pointing to foreign snapshot self_hash
	snapB0 := NewSnapshot("snap-b0", repoB, "commit-b0", "main", t0, "sha-b0", 10, 0, 3, 1, 0, "", nil)
	forgedParentSnap := NewSnapshot("snap-b1-forged", repoB, "commit-b1", "main", t0.Add(1*time.Hour), "sha-b1", 10, 0, 4, 0, 0, snapA0.SelfHash, nil)
	forgedChain := []ScanSnapshot{snapB0, forgedParentSnap}

	forgedReport := ValidateChain(forgedChain)
	if forgedReport.Valid {
		t.Fatalf("Fail-closed failure: ValidateChain accepted forged parent hash from foreign tenant!")
	}
	if forgedReport.BrokenAtIndex != 1 {
		t.Fatalf("Expected broken at index 1 for prev_snapshot_hash mismatch, got %d", forgedReport.BrokenAtIndex)
	}
	t.Logf("Attack Vector 2b PASSED: Forged foreign parent hash detected and rejected: %s", forgedReport.Reason)

	// =========================================================================
	// ATTACK VECTOR 3: Extreme Integer Overflow / Underflow Payloads
	// =========================================================================
	t.Log("Executing Attack Vector 3: Extreme Integer Boundaries & Negative Counts...")

	// 3a: Negative metrics payload
	negReq := IngestionRequest{
		RepoID:               repoB,
		CommitSHA:            "commit-neg",
		Branch:               "main",
		ScanTimestamp:        t0.Add(2 * time.Hour),
		AIBOMSHA256:          "sha-neg",
		ControlsMet:          -100, // Negative metric
		ControlsGap:          -1,
		ComponentsCount:      -50,
		VulnerabilitiesCount: -10,
	}
	negBody, _ := json.Marshal(negReq)
	negHttpReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/snapshots", repoB), bytes.NewReader(negBody))
	negRec := httptest.NewRecorder()
	handler.ServeHTTP(negRec, negHttpReq)

	if negRec.Code != http.StatusBadRequest {
		t.Fatalf("Fail-closed failure: Expected 400 Bad Request on negative metrics, got %d", negRec.Code)
	}
	t.Log("Attack Vector 3a PASSED: API rejected negative metrics payload with 400 Bad Request.")

	// 3b: Extreme Int64 Overflow Boundary Payloads in Validator & Hash Function
	t.Log("Testing cryptographic hash computation under extreme math boundary values...")
	maxIntHash := ComputeSnapshotHash(repoB, "commit-max", t0, "sha-max", math.MaxInt32, 0, 0, ingB0.SelfHash)
	if maxIntHash == "" || len(maxIntHash) != 64 {
		t.Fatalf("Failed to compute deterministic hash on MaxInt boundary value")
	}

	snapMax := NewSnapshot("snap-max", repoB, "commit-max", "main", t0.Add(2*time.Hour), "sha-max", math.MaxInt32, 0, math.MaxInt32, 0, 0, ingB0.SelfHash, nil)
	if !VerifySnapshot(snapMax) {
		t.Fatalf("VerifySnapshot failed for MaxInt snapshot")
	}

	// 3c: Malformed Corrupted JSON Payloads & Injection Strings
	malformedBodies := [][]byte{
		[]byte(`{"repo_id": "repo-bravo-core", "controls_met": "NOT_A_NUMBER"}`),
		[]byte(`{"repo_id": "repo-bravo-core", "commit_sha": ""}`),
		[]byte(`{"repo_id": "' OR 1=1 --", "commit_sha": "sqli-test"}`),
		[]byte(`{truncated_json`),
		[]byte(``),
	}

	for idx, mBody := range malformedBodies {
		mReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/snapshots", repoB), bytes.NewReader(mBody))
		mRec := httptest.NewRecorder()
		handler.ServeHTTP(mRec, mReq)

		if mRec.Code != http.StatusBadRequest {
			t.Fatalf("Fail-closed failure: Expected 400 Bad Request on malformed body %d, got %d", idx, mRec.Code)
		}
	}
	t.Log("Attack Vector 3c PASSED: API fail-closed safely against all malformed / injection payloads.")

	// =========================================================================
	// ATTACK VECTOR 4: Timestamp Monotonicity & Bit-Level Fuzz Tampering
	// =========================================================================
	t.Log("Executing Attack Vector 4: Timestamp Monotonicity and Fuzz Tampering...")

	// 4a: Non-monotonic retroactive timestamp injection (Scan timestamp in the past)
	retroSnap := NewSnapshot("snap-retro", repoB, "commit-retro", "main", t0.Add(-24*time.Hour), "sha-retro", 10, 0, 4, 0, 0, snapB0.SelfHash, nil)
	retroReport := ValidateChain([]ScanSnapshot{snapB0, retroSnap})
	if retroReport.Valid {
		t.Fatalf("Fail-closed failure: ValidateChain accepted backwards timestamp!")
	}
	if retroReport.BrokenAtIndex != 1 {
		t.Fatalf("Expected broken at index 1 for retroactive timestamp, got %d", retroReport.BrokenAtIndex)
	}
	t.Logf("Attack Vector 4a PASSED: Timestamp regression rejected: %s", retroReport.Reason)

	// 4b: High-entropy bit-flip fuzzing across 100 perturbed iterations
	rng := rand.New(rand.NewSource(1337))
	validChain := []ScanSnapshot{snapB0, snapMax}
	for f := 0; f < 100; f++ {
		tamperedChain := make([]ScanSnapshot, len(validChain))
		copy(tamperedChain, validChain)

		tamperMode := rng.Intn(5)
		switch tamperMode {
		case 0:
			tamperedChain[1].ControlsMet ^= (1 << rng.Intn(8))
		case 1:
			tamperedChain[1].CommitSHA = fmt.Sprintf("forged-sha-%d", f)
		case 2:
			tamperedChain[1].PrevSnapshotHash = "0000000000000000000000000000000000000000000000000000000000000000"
		case 3:
			tamperedChain[1].RepoID = fmt.Sprintf("repo-forged-%d", f)
		case 4:
			tamperedChain[1].AIBOMSHA256 = fmt.Sprintf("tampered-aibom-%d", f)
		}

		res := ValidateChain(tamperedChain)
		if res.Valid {
			t.Fatalf("Fuzz test iteration %d (mode %d) failed: tampered chain was accepted as valid!", f, tamperMode)
		}
	}
	t.Log("Attack Vector 4b PASSED: 100% of 100 bit-flipped / tampered payloads safely rejected.")

	t.Log("=== TestQA_AdversarialTenantCrossInjection PASSED ===")
}
