package compliancedb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestQA_ExtremeChainScale_10K stresses the hash-chain ledger across 10,000 snapshots.
// It verifies:
//  1. Continuous 10,000-node ledger generation & zero bit-drift cryptographic chain validation.
//  2. Validation latency & throughput at 10,000 scale.
//  3. Precision tampering detection at the ultimate node (index 9,999) under multiple mutation vectors.
//  4. Deep mid-chain and genesis tampering isolation.
func TestQA_ExtremeChainScale_10K(t *testing.T) {
	const chainLength = 10000
	repoID := "repo-scale-extreme-10k"
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rng := rand.New(rand.NewSource(42))

	t.Logf("=== QA Extreme Chain Scale 10K Test Started ===")
	t.Logf("Generating %d hash-chained snapshots...", chainLength)

	genStart := time.Now()
	chain := make([]ScanSnapshot, chainLength)
	prevHash := ""

	for i := 0; i < chainLength; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Minute)
		cSum := sha256.Sum256([]byte(fmt.Sprintf("%d", i)))
		commitSHA := fmt.Sprintf("commit-%05d-%x", i, cSum[:4])
		aSum := sha256.Sum256([]byte(commitSHA))
		aibomSHA := fmt.Sprintf("aibom-sha256-%05d-%x", i, aSum[:8])

		met := 10 + (i % 20)
		gap := (i % 5)
		manual := (i % 3)
		compCount := 100 + (i % 50)
		vulnCount := (i % 10)

		rawAIBOM := json.RawMessage(fmt.Sprintf(`{"snapshotIndex":%d,"timestamp":"%s","components":%d}`, i, ts.Format(time.RFC3339), compCount))

		chain[i] = NewSnapshot(
			fmt.Sprintf("snap-scale-%05d", i),
			repoID,
			commitSHA,
			"main",
			ts,
			aibomSHA,
			compCount,
			vulnCount,
			met,
			gap,
			manual,
			prevHash,
			rawAIBOM,
		)
		prevHash = chain[i].SelfHash
	}
	genDuration := time.Since(genStart)
	t.Logf("Generated %d snapshots in %v (throughput: %.2f snaps/sec)", chainLength, genDuration, float64(chainLength)/genDuration.Seconds())

	// Step 1: Zero Bit-Drift Verification
	t.Log("Validating zero bit-drift across 10,000 snapshots...")
	for i := 0; i < chainLength; i++ {
		if !VerifySnapshot(chain[i]) {
			t.Fatalf("snapshot %d internal verification failed (bit drift detected)", i)
		}
		if i > 0 {
			if chain[i].PrevSnapshotHash != chain[i-1].SelfHash {
				t.Fatalf("snapshot %d PrevSnapshotHash (%s) != snapshot %d SelfHash (%s)", i, chain[i].PrevSnapshotHash, i-1, chain[i-1].SelfHash)
			}
			if chain[i].ScanTimestamp.Before(chain[i-1].ScanTimestamp) {
				t.Fatalf("snapshot %d timestamp non-monotonic: %v < %v", i, chain[i].ScanTimestamp, chain[i-1].ScanTimestamp)
			}
		} else {
			if chain[0].PrevSnapshotHash != "" {
				t.Fatalf("genesis snapshot PrevSnapshotHash is non-empty: %s", chain[0].PrevSnapshotHash)
			}
		}
	}

	// Step 2: Full Cryptographic Chain Validation
	valStart := time.Now()
	report := ValidateChain(chain)
	valDuration := time.Since(valStart)

	t.Logf("Full ValidateChain() for 10,000 snapshots completed in %v", valDuration)
	t.Logf("Validation Throughput: %.2f snapshots/sec (%.3f µs/snapshot)",
		float64(chainLength)/valDuration.Seconds(),
		float64(valDuration.Microseconds())/float64(chainLength))

	if !report.Valid {
		t.Fatalf("expected pristine 10,000-snapshot chain to be valid, got broken at index %d: %s", report.BrokenAtIndex, report.Reason)
	}
	if report.TotalSnapshots != chainLength {
		t.Fatalf("expected TotalSnapshots=%d, got %d", chainLength, report.TotalSnapshots)
	}
	if report.BrokenAtIndex != -1 {
		t.Fatalf("expected BrokenAtIndex=-1, got %d", report.BrokenAtIndex)
	}

	// Step 3: Precision Tampering Detection at Index 9,999 (Ultimate Node)
	t.Log("Testing tampering detection at ultimate node index 9,999...")

	// Vector 3a: Tamper ControlsMet metric at index 9,999
	{
		tamperedChain := make([]ScanSnapshot, chainLength)
		copy(tamperedChain, chain)
		tamperedChain[9999].ControlsMet += 1

		tamperReport := ValidateChain(tamperedChain)
		if tamperReport.Valid {
			t.Fatal("expected tampering at index 9999 (ControlsMet) to fail validation, but passed")
		}
		if tamperReport.BrokenAtIndex != 9999 {
			t.Fatalf("expected BrokenAtIndex=9999, got %d", tamperReport.BrokenAtIndex)
		}
		if tamperReport.BrokenSnapshot == nil || *tamperReport.BrokenSnapshot != chain[9999].ID {
			t.Fatalf("expected BrokenSnapshot=%s, got %v", chain[9999].ID, tamperReport.BrokenSnapshot)
		}
		t.Logf("Vector 3a (ControlsMet tamper at 9999) PASSED: %s", tamperReport.Reason)
	}

	// Vector 3b: Tamper AIBOM SHA256 at index 9,999
	{
		tamperedChain := make([]ScanSnapshot, chainLength)
		copy(tamperedChain, chain)
		tamperedChain[9999].AIBOMSHA256 = "forged-aibom-hash-at-9999"

		tamperReport := ValidateChain(tamperedChain)
		if tamperReport.Valid {
			t.Fatal("expected tampering at index 9999 (AIBOMSHA256) to fail validation, but passed")
		}
		if tamperReport.BrokenAtIndex != 9999 {
			t.Fatalf("expected BrokenAtIndex=9999, got %d", tamperReport.BrokenAtIndex)
		}
		t.Logf("Vector 3b (AIBOM SHA tamper at 9999) PASSED: %s", tamperReport.Reason)
	}

	// Vector 3c: Tamper PrevSnapshotHash continuity link at index 9,999
	{
		tamperedChain := make([]ScanSnapshot, chainLength)
		copy(tamperedChain, chain)
		// Alter prev hash AND recompute selfHash so self-hash is valid but parent continuity is broken
		tamperedChain[9999].PrevSnapshotHash = "forged-parent-hash-9998"
		tamperedChain[9999].SelfHash = ComputeSnapshotHash(
			tamperedChain[9999].RepoID,
			tamperedChain[9999].CommitSHA,
			tamperedChain[9999].ScanTimestamp,
			tamperedChain[9999].AIBOMSHA256,
			tamperedChain[9999].ControlsMet,
			tamperedChain[9999].ControlsGap,
			tamperedChain[9999].ControlsManual,
			tamperedChain[9999].PrevSnapshotHash,
		)

		tamperReport := ValidateChain(tamperedChain)
		if tamperReport.Valid {
			t.Fatal("expected parent link break at index 9999 to fail validation, but passed")
		}
		if tamperReport.BrokenAtIndex != 9999 {
			t.Fatalf("expected BrokenAtIndex=9999, got %d", tamperReport.BrokenAtIndex)
		}
		t.Logf("Vector 3c (Parent link break at 9999) PASSED: %s", tamperReport.Reason)
	}

	// Vector 3d: Tamper ScanTimestamp chronological monotonicity at index 9,999
	{
		tamperedChain := make([]ScanSnapshot, chainLength)
		copy(tamperedChain, chain)
		// Set timestamp earlier than snapshot 9998 and recompute selfHash
		tamperedChain[9999].ScanTimestamp = tamperedChain[9998].ScanTimestamp.Add(-10 * time.Minute)
		tamperedChain[9999].SelfHash = ComputeSnapshotHash(
			tamperedChain[9999].RepoID,
			tamperedChain[9999].CommitSHA,
			tamperedChain[9999].ScanTimestamp,
			tamperedChain[9999].AIBOMSHA256,
			tamperedChain[9999].ControlsMet,
			tamperedChain[9999].ControlsGap,
			tamperedChain[9999].ControlsManual,
			tamperedChain[9999].PrevSnapshotHash,
		)

		tamperReport := ValidateChain(tamperedChain)
		if tamperReport.Valid {
			t.Fatal("expected non-monotonic timestamp at index 9999 to fail validation, but passed")
		}
		if tamperReport.BrokenAtIndex != 9999 {
			t.Fatalf("expected BrokenAtIndex=9999, got %d", tamperReport.BrokenAtIndex)
		}
		t.Logf("Vector 3d (Timestamp regression at 9999) PASSED: %s", tamperReport.Reason)
	}

	// Step 4: Multi-Point Random Tampering Stress
	t.Log("Testing random index tampering stress across 10,000 snapshots...")
	testIndices := []int{0, 1, 500, 2500, 5000, 7500, 9998}
	for _, idx := range testIndices {
		tamperedChain := make([]ScanSnapshot, chainLength)
		copy(tamperedChain, chain)
		tamperedChain[idx].CommitSHA = fmt.Sprintf("corrupted-commit-%d", rng.Intn(100000))

		res := ValidateChain(tamperedChain)
		if res.Valid {
			t.Fatalf("expected tampering at index %d to fail validation, but passed", idx)
		}
		if res.BrokenAtIndex != idx {
			t.Fatalf("expected BrokenAtIndex=%d, got %d", idx, res.BrokenAtIndex)
		}
	}

	t.Logf("=== QA Extreme Chain Scale 10K Test PASSED ===")
}

// TestQA_ConcurrentAPIStorm_100Workers stresses the ComplianceDB REST API with 100 concurrent workers.
// It executes 1,000+ total HTTP requests across:
//  - POST /api/v1/repos/{repo}/snapshots (ledger ingestion + incident lifecycle)
//  - GET /api/v1/repos/{repo}/history (snapshot ledger retrieval + cryptographic verification)
//  - GET /api/v1/orgs/{org}/compliance (cross-repository multi-regulation aggregation)
//
// Assertions:
//  - 0 dropped requests
//  - 0 deadlocks (protected by context timeout)
//  - 100% 200 OK / 201 Created HTTP responses
//  - Post-storm cryptographic chain verification across all repositories
func TestQA_ConcurrentAPIStorm_100Workers(t *testing.T) {
	const numWorkers = 100
	const iterationsPerWorker = 30 // 100 workers * 30 iterations * 3 ops = 9,000 total HTTP requests
	const numOrgs = 5
	const reposPerOrg = 20 // 100 total repos (1 per worker)

	t.Logf("=== QA Concurrent API Storm (100 Workers) Test Started ===")
	t.Logf("Target: %d workers x %d iterations x 3 endpoints = %d requests",
		numWorkers, iterationsPerWorker, numWorkers*iterationsPerWorker*3)

	svc := NewService()

	// Seed Organizations and Repositories
	for o := 0; o < numOrgs; o++ {
		orgID := fmt.Sprintf("org-storm-%02d", o)
		svc.RegisterOrg(Organization{
			ID:        orgID,
			Slug:      fmt.Sprintf("slug-storm-%02d", o),
			Name:      fmt.Sprintf("Storm Enterprise Tenant %02d", o),
			CreatedAt: time.Now().UTC(),
		})

		for r := 0; r < reposPerOrg; r++ {
			globalRepoIdx := o*reposPerOrg + r
			repoID := fmt.Sprintf("repo-storm-%03d", globalRepoIdx)
			svc.RegisterRepo(Repository{
				ID:            repoID,
				OrgID:         orgID,
				GitURL:        fmt.Sprintf("https://github.com/airom-storm/%s.git", repoID),
				DefaultBranch: "main",
				CreatedAt:     time.Now().UTC(),
			})
		}
	}

	handler := svc.Routes()

	// Atomic telemetry metrics
	var (
		totalRequests        int64
		postSnapshotsTotal   int64
		postSnapshots201     int64
		getHistoryTotal      int64
		getHistory200        int64
		getComplianceTotal   int64
		getCompliance200     int64
		errorCount           int64
	)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	baseTime := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup

	stormStart := time.Now()

	// Launch 100 concurrent worker goroutines
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			repoID := fmt.Sprintf("repo-storm-%03d", workerID)
			orgID := fmt.Sprintf("org-storm-%02d", workerID/reposPerOrg)

			for iter := 0; iter < iterationsPerWorker; iter++ {
				select {
				case <-ctx.Done():
					atomic.AddInt64(&errorCount, 1)
					return
				default:
				}

				iterTime := baseTime.Add(time.Duration(iter*10) * time.Second)
				commitSHA := fmt.Sprintf("commit-%03d-%03d", workerID, iter)
				cSum := sha256.Sum256([]byte(commitSHA))
				aibomHash := fmt.Sprintf("aibom-%03d-%03d-%x", workerID, iter, cSum[:4])

				// Operation 1: POST /api/v1/repos/{repo}/snapshots
				evalVerdict := VerdictMet
				gapCount := 0
				metCount := 3
				if iter%3 == 1 {
					evalVerdict = VerdictGap
					gapCount = 1
					metCount = 2
				}

				ingReq := IngestionRequest{
					RepoID:               repoID,
					CommitSHA:            commitSHA,
					Branch:               "main",
					ScanTimestamp:        iterTime,
					AIBOMSHA256:          aibomHash,
					ComponentsCount:      45 + (iter % 10),
					VulnerabilitiesCount: iter % 2,
					ControlsMet:          metCount,
					ControlsGap:          gapCount,
					ControlsManual:       0,
					Evaluations: []ControlEvaluation{
						{
							ControlID:  "co.ai-act.impact-assessment",
							StatuteRef: "CO SB 24-205 §6-1-1703",
							Verdict:    evalVerdict,
							GapMessage: "Evaluation assessment during storm iteration",
						},
						{
							ControlID:  "nyc.ll144.bias-audit",
							StatuteRef: "NYC LL144 §20-871",
							Verdict:    VerdictMet,
						},
						{
							ControlID:  "ca.ab2013.training-data",
							StatuteRef: "CA AB 2013 §3100",
							Verdict:    VerdictMet,
						},
					},
					RawAIBOM: json.RawMessage(fmt.Sprintf(`{"worker":%d,"iter":%d}`, workerID, iter)),
				}

				reqBytes, _ := json.Marshal(ingReq)
				postReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/snapshots", repoID), bytes.NewReader(reqBytes))
				postReq = postReq.WithContext(ctx)
				postReq.Header.Set("Content-Type", "application/json")
				postRec := httptest.NewRecorder()

				atomic.AddInt64(&totalRequests, 1)
				atomic.AddInt64(&postSnapshotsTotal, 1)

				handler.ServeHTTP(postRec, postReq)
				if postRec.Code == http.StatusCreated {
					atomic.AddInt64(&postSnapshots201, 1)
				} else {
					atomic.AddInt64(&errorCount, 1)
				}

				// Operation 2: GET /api/v1/repos/{repo}/history
				histReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/repos/%s/history", repoID), nil)
				histReq = histReq.WithContext(ctx)
				histRec := httptest.NewRecorder()

				atomic.AddInt64(&totalRequests, 1)
				atomic.AddInt64(&getHistoryTotal, 1)

				handler.ServeHTTP(histRec, histReq)
				if histRec.Code == http.StatusOK {
					atomic.AddInt64(&getHistory200, 1)
				} else {
					atomic.AddInt64(&errorCount, 1)
				}

				// Operation 3: GET /api/v1/orgs/{org}/compliance
				compReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/orgs/%s/compliance", orgID), nil)
				compReq = compReq.WithContext(ctx)
				compRec := httptest.NewRecorder()

				atomic.AddInt64(&totalRequests, 1)
				atomic.AddInt64(&getComplianceTotal, 1)

				handler.ServeHTTP(compRec, compReq)
				if compRec.Code == http.StatusOK {
					atomic.AddInt64(&getCompliance200, 1)
				} else {
					atomic.AddInt64(&errorCount, 1)
				}
			}
		}(w)
	}

	// Wait for workers or timeout deadlock detection
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
	case <-time.After(40 * time.Second):
		t.Fatal("DEADLOCK DETECTED: 100-worker storm failed to complete within 40s timeout")
	}

	stormDuration := time.Since(stormStart)
	totalReqCompleted := atomic.LoadInt64(&totalRequests)
	errs := atomic.LoadInt64(&errorCount)
	pTotal := atomic.LoadInt64(&postSnapshotsTotal)
	p201 := atomic.LoadInt64(&postSnapshots201)
	hTotal := atomic.LoadInt64(&getHistoryTotal)
	h200 := atomic.LoadInt64(&getHistory200)
	cTotal := atomic.LoadInt64(&getComplianceTotal)
	c200 := atomic.LoadInt64(&getCompliance200)

	rps := float64(totalReqCompleted) / stormDuration.Seconds()

	t.Logf("Storm Results Summary:")
	t.Logf("  Total Requests: %d in %v (Throughput: %.2f HTTP reqs/sec)", totalReqCompleted, stormDuration, rps)
	t.Logf("  POST /snapshots: %d total, %d 201 Created (%.2f%%)", pTotal, p201, float64(p201)/float64(pTotal)*100)
	t.Logf("  GET /history:    %d total, %d 200 OK (%.2f%%)", hTotal, h200, float64(h200)/float64(hTotal)*100)
	t.Logf("  GET /compliance: %d total, %d 200 OK (%.2f%%)", cTotal, c200, float64(c200)/float64(cTotal)*100)
	t.Logf("  Errors / Dropped: %d", errs)

	// Strict QA Assertions
	if totalReqCompleted < 1000 {
		t.Fatalf("expected at least 1,000 total requests, got %d", totalReqCompleted)
	}
	if errs != 0 {
		t.Fatalf("expected 0 dropped/errored requests, got %d", errs)
	}
	if p201 != pTotal {
		t.Fatalf("expected 100%% 201 Created for POST /snapshots (%d != %d)", p201, pTotal)
	}
	if h200 != hTotal {
		t.Fatalf("expected 100%% 200 OK for GET /history (%d != %d)", h200, hTotal)
	}
	if c200 != cTotal {
		t.Fatalf("expected 100%% 200 OK for GET /compliance (%d != %d)", c200, cTotal)
	}

	// Post-Storm Full Ledger Integrity Audit across all 100 repos
	t.Log("Performing post-storm full cryptographic ledger audit across all 100 repositories...")
	for w := 0; w < numWorkers; w++ {
		repoID := fmt.Sprintf("repo-storm-%03d", w)
		hReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/repos/%s/history", repoID), nil)
		hRec := httptest.NewRecorder()
		handler.ServeHTTP(hRec, hReq)

		if hRec.Code != http.StatusOK {
			t.Fatalf("post-storm audit failed to fetch history for %s: code %d", repoID, hRec.Code)
		}

		var hist RepoHistoryResponse
		if err := json.NewDecoder(hRec.Body).Decode(&hist); err != nil {
			t.Fatalf("post-storm audit failed to decode json for %s: %v", repoID, err)
		}

		if hist.TotalCount != iterationsPerWorker {
			t.Fatalf("repo %s: expected %d snapshots, got %d", repoID, iterationsPerWorker, hist.TotalCount)
		}
		if !hist.ChainReport.Valid {
			t.Fatalf("repo %s: chain corrupted post-storm at index %d: %s", repoID, hist.ChainReport.BrokenAtIndex, hist.ChainReport.Reason)
		}
	}
	t.Log("Post-storm ledger audit PASSED: All 100 repository hash chains are intact and valid.")
	t.Logf("=== QA Concurrent API Storm Test PASSED ===")
}

// BenchmarkScale_10KSnapshotValidation benchmarks pure cryptographic validation over a 10,000-node ledger.
func BenchmarkScale_10KSnapshotValidation(b *testing.B) {
	const chainLength = 10000
	repoID := "repo-bench-10k"
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	chain := make([]ScanSnapshot, chainLength)
	prevHash := ""
	for i := 0; i < chainLength; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Minute)
		chain[i] = NewSnapshot(
			fmt.Sprintf("snap-%05d", i),
			repoID,
			fmt.Sprintf("commit-%05d", i),
			"main",
			ts,
			fmt.Sprintf("aibom-%05d", i),
			100,
			0,
			15,
			0,
			0,
			prevHash,
			nil,
		)
		prevHash = chain[i].SelfHash
	}

	b.ResetTimer()
	b.SetBytes(int64(chainLength))

	for i := 0; i < b.N; i++ {
		report := ValidateChain(chain)
		if !report.Valid {
			b.Fatalf("validation failed at index %d", report.BrokenAtIndex)
		}
	}
}

// BenchmarkScale_ConcurrentIngestion benchmarks concurrent HTTP snapshot ingestion throughput across multiple workers.
func BenchmarkScale_ConcurrentIngestion(b *testing.B) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	client := ts.Client()
	baseTime := time.Now().UTC()

	var counter int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := atomic.AddInt64(&counter, 1)
			repoID := fmt.Sprintf("repo-bench-%02d", idx%20)
			req := IngestionRequest{
				RepoID:          repoID,
				CommitSHA:       fmt.Sprintf("commit-%d", idx),
				Branch:          "main",
				ScanTimestamp:   baseTime.Add(time.Duration(idx) * time.Millisecond),
				AIBOMSHA256:     fmt.Sprintf("aibom-%d", idx),
				ComponentsCount: 50,
				ControlsMet:     10,
				ControlsGap:     0,
				ControlsManual:  0,
			}
			reqBytes, _ := json.Marshal(req)
			resp, err := client.Post(fmt.Sprintf("%s/api/v1/repos/%s/snapshots", ts.URL, repoID), "application/json", bytes.NewReader(reqBytes))
			if err == nil {
				resp.Body.Close()
			}
		}
	})
}
