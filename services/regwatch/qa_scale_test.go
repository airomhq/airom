package regwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestQA_ExtremeStatuteDiffScale_10KSections tests diff computation on two massive 10,000-section regulatory corpora.
func TestQA_ExtremeStatuteDiffScale_10KSections(t *testing.T) {
	diffEngine := NewDiffEngine()

	const (
		numRemoved   = 2000
		numModified  = 2000
		numUnchanged = 6000
		numAdded     = 2000
		totalOld     = numRemoved + numModified + numUnchanged // 10,000
		totalNew     = numAdded + numModified + numUnchanged   // 10,000
	)

	// Construct old statutory document with 10,000 sections
	oldSections := make([]StatuteSection, 0, totalOld)
	for i := 0; i < numRemoved; i++ {
		oldSections = append(oldSections, StatuteSection{
			ID:      fmt.Sprintf("SEC-REM-%05d", i),
			Title:   fmt.Sprintf("Legacy Model Registration Clause %d", i),
			Content: fmt.Sprintf("High-risk AI system deployers must register algorithmic telemetry with regional oversight bureau clause %d.", i),
		})
	}
	for i := 0; i < numModified; i++ {
		oldSections = append(oldSections, StatuteSection{
			ID:      fmt.Sprintf("SEC-MOD-%05d", i),
			Title:   fmt.Sprintf("Algorithmic Transparency Obligation %d", i),
			Content: fmt.Sprintf("Deployers shall provide general technical documentation for algorithmic tools in category %d.", i),
		})
	}
	for i := 0; i < numUnchanged; i++ {
		oldSections = append(oldSections, StatuteSection{
			ID:      fmt.Sprintf("SEC-UNC-%05d", i),
			Title:   fmt.Sprintf("Standard Statutory Definition %d", i),
			Content: fmt.Sprintf("For the purposes of this statute, artificial intelligence system definition clause %d remains in full effect.", i),
		})
	}

	oldDoc := StatutoryDocument{
		Jurisdiction:  JurisdictionEU,
		Title:         "Regulation (EU) 2024/1689 - Extended Corpus Scale Baseline",
		SourceURL:     "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
		Version:       "2026.1",
		EffectiveDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Sections:      oldSections,
	}
	oldDoc.ComputeHash()

	// Construct new statutory document with 10,000 sections (2,000 added, 2,000 modified, 6,000 unchanged)
	newSections := make([]StatuteSection, 0, totalNew)
	for i := 0; i < numAdded; i++ {
		newSections = append(newSections, StatuteSection{
			ID:      fmt.Sprintf("SEC-ADD-%05d", i),
			Title:   fmt.Sprintf("Enacted Continuous Audit Mandate %d", i),
			Content: fmt.Sprintf("Deployers must submit to mandatory annual third-party bias audit under penalty of fine for clause %d.", i),
		})
	}
	for i := 0; i < numModified; i++ {
		newSections = append(newSections, StatuteSection{
			ID:      fmt.Sprintf("SEC-MOD-%05d", i),
			Title:   fmt.Sprintf("Algorithmic Transparency Obligation %d", i),
			Content: fmt.Sprintf("Deployers shall provide general technical documentation for algorithmic tools in category %d, and must submit mandatory third-party audit reports under penalty of statutory fine.", i),
		})
	}
	for i := 0; i < numUnchanged; i++ {
		newSections = append(newSections, StatuteSection{
			ID:      fmt.Sprintf("SEC-UNC-%05d", i),
			Title:   fmt.Sprintf("Standard Statutory Definition %d", i),
			Content: fmt.Sprintf("For the purposes of this statute, artificial intelligence system definition clause %d remains in full effect.", i),
		})
	}

	newDoc := StatutoryDocument{
		Jurisdiction:  JurisdictionEU,
		Title:         "Regulation (EU) 2024/1689 - Extended Corpus Scale Revision",
		SourceURL:     "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
		Version:       "2026.2",
		EffectiveDate: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC),
		Sections:      newSections,
	}
	newDoc.ComputeHash()

	if len(oldDoc.Sections) != 10000 {
		t.Fatalf("expected 10,000 old sections, got %d", len(oldDoc.Sections))
	}
	if len(newDoc.Sections) != 10000 {
		t.Fatalf("expected 10,000 new sections, got %d", len(newDoc.Sections))
	}

	// Warmup execution
	_ = diffEngine.ComputeDiff(oldDoc, newDoc)

	// Measure diff performance
	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	diff := diffEngine.ComputeDiff(oldDoc, newDoc)
	duration := time.Since(start)

	runtime.ReadMemStats(&memAfter)

	// Verification of Delta Accuracy
	if !diff.HasChanges {
		t.Fatal("expected diff to report changes")
	}
	if diff.MaxSeverity != SeverityBreaking {
		t.Errorf("expected max severity BREAKING, got %s", diff.MaxSeverity)
	}

	expectedTotalDeltas := numAdded + numModified + numRemoved // 6,000
	if len(diff.SectionDeltas) != expectedTotalDeltas {
		t.Fatalf("expected %d total deltas, got %d", expectedTotalDeltas, len(diff.SectionDeltas))
	}

	addedCount := 0
	modifiedCount := 0
	removedCount := 0

	deltaMap := make(map[string]SectionDelta, len(diff.SectionDeltas))
	for _, delta := range diff.SectionDeltas {
		deltaMap[delta.SectionID] = delta
		switch delta.ChangeType {
		case "ADDED":
			addedCount++
		case "MODIFIED":
			modifiedCount++
		case "REMOVED":
			removedCount++
		default:
			t.Errorf("unexpected change type: %s for section %s", delta.ChangeType, delta.SectionID)
		}
	}

	if addedCount != numAdded {
		t.Errorf("expected %d ADDED sections, got %d", numAdded, addedCount)
	}
	if modifiedCount != numModified {
		t.Errorf("expected %d MODIFIED sections, got %d", numModified, modifiedCount)
	}
	if removedCount != numRemoved {
		t.Errorf("expected %d REMOVED sections, got %d", numRemoved, removedCount)
	}

	// Assert 100% delta detection accuracy across all generated IDs
	for i := 0; i < numAdded; i++ {
		id := fmt.Sprintf("SEC-ADD-%05d", i)
		delta, ok := deltaMap[id]
		if !ok || delta.ChangeType != "ADDED" {
			t.Errorf("missing or incorrect delta for added section %s", id)
		}
		if delta.Severity != SeverityBreaking {
			t.Errorf("expected severity BREAKING for added section %s, got %s", id, delta.Severity)
		}
	}
	for i := 0; i < numModified; i++ {
		id := fmt.Sprintf("SEC-MOD-%05d", i)
		delta, ok := deltaMap[id]
		if !ok || delta.ChangeType != "MODIFIED" {
			t.Errorf("missing or incorrect delta for modified section %s", id)
		}
		if delta.Severity != SeverityBreaking {
			t.Errorf("expected severity BREAKING for modified section %s, got %s", id, delta.Severity)
		}
	}
	for i := 0; i < numRemoved; i++ {
		id := fmt.Sprintf("SEC-REM-%05d", i)
		delta, ok := deltaMap[id]
		if !ok || delta.ChangeType != "REMOVED" {
			t.Errorf("missing or incorrect delta for removed section %s", id)
		}
		if delta.Severity != SeverityBreaking {
			t.Errorf("expected severity BREAKING for removed section %s, got %s", id, delta.Severity)
		}
	}

	totalEvaluatedSections := len(oldDoc.Sections) + len(newDoc.Sections) // 20,000 sections
	sectionsPerSec := float64(totalEvaluatedSections) / duration.Seconds()

	t.Logf("=== Extreme Statute Diff Scale Results ===")
	t.Logf("Old Sections: %d | New Sections: %d | Total Evaluated: %d", len(oldDoc.Sections), len(newDoc.Sections), totalEvaluatedSections)
	t.Logf("Deltas Detected: %d (Added: %d, Modified: %d, Removed: %d)", len(diff.SectionDeltas), addedCount, modifiedCount, removedCount)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f sections/sec", sectionsPerSec)
	t.Logf("Heap Alloc Delta: %.2f KB", float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/1024.0)

	// Assert sub-second execution (< 1.0s)
	if duration >= 1*time.Second {
		t.Errorf("expected sub-second execution, took %v", duration)
	}

	// Assert throughput > 100,000 sections/sec
	if sectionsPerSec < 100000.0 {
		t.Errorf("expected throughput > 100,000 sections/sec, got %.2f", sectionsPerSec)
	}
}

// TestQA_ConcurrentFeedScraperStorm_100Workers spawns 100 concurrent workers executing 5,000 live queries across 8 jurisdictions.
func TestQA_ConcurrentFeedScraperStorm_100Workers(t *testing.T) {
	allJurisdictions := []Jurisdiction{
		JurisdictionColorado,
		JurisdictionCalifornia,
		JurisdictionNYC,
		JurisdictionEU,
		JurisdictionIllinois,
		JurisdictionTexas,
		JurisdictionVirginia,
		JurisdictionUSFederal,
	}

	var httpReqCount int64

	// Spin up mock HTTP feed server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&httpReqCount, 1)
		path := r.URL.Path

		matchedJ := JurisdictionEU
		for _, j := range allJurisdictions {
			if strings.Contains(path, string(j)) {
				matchedJ = j
				break
			}
		}

		doc := StatutoryDocument{
			Jurisdiction:  matchedJ,
			Title:         fmt.Sprintf("Live Statutory Feed for %s", matchedJ),
			SourceURL:     r.URL.String(),
			Version:       "2026.9-STORM",
			EffectiveDate: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			Sections: []StatuteSection{
				{
					ID:      fmt.Sprintf("%s-CORE-01", matchedJ),
					Title:   "Mandatory Risk Governance & Algorithmic Oversight",
					Content: "Deployers shall execute continuous algorithmic risk audits and maintain real-time compliance attestations under penalty of statutory fine.",
				},
				{
					ID:      fmt.Sprintf("%s-CORE-02", matchedJ),
					Title:   "Automated Incident Notification",
					Content: "Deployers must notify oversight authorities within 72 hours of any high-risk algorithmic malfunction or discrimination anomaly.",
				},
			},
		}
		doc.ComputeHash()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer server.Close()

	customEndpoints := make(map[Jurisdiction]string)
	for _, j := range allJurisdictions {
		customEndpoints[j] = fmt.Sprintf("%s/%s", server.URL, j)
	}

	cfg := ScraperConfig{
		ClientTimeoutSec: 10,
		CustomEndpoints:  customEndpoints,
	}

	svc := NewService(cfg)

	var (
		receivedAlertsCount int64
		receivedAlertsMu    sync.Mutex
		receivedAlerts      []RegulatoryAlert
	)

	// Subscribe alert listener
	svc.SubscribeAlerts(func(alert RegulatoryAlert) {
		atomic.AddInt64(&receivedAlertsCount, 1)
		receivedAlertsMu.Lock()
		receivedAlerts = append(receivedAlerts, alert)
		receivedAlertsMu.Unlock()
	})

	const (
		totalQueries = 5000
		numWorkers   = 100
	)

	tasks := make(chan int, totalQueries)
	for i := 0; i < totalQueries; i++ {
		tasks <- i
	}
	close(tasks)

	var (
		completedChecks      int64
		droppedChecks        int64
		generatedAlertsCount int64
	)

	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	start := time.Now()

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case taskID, ok := <-tasks:
					if !ok {
						return
					}
					// 1 in 10 queries tests CheckAllJurisdictions, others test CheckJurisdiction
					if taskID%10 == 0 {
						diffs, alerts, err := svc.CheckAllJurisdictions(ctx)
						if err != nil {
							atomic.AddInt64(&droppedChecks, 1)
						} else {
							atomic.AddInt64(&completedChecks, 1)
							atomic.AddInt64(&generatedAlertsCount, int64(len(alerts)))
							_ = diffs
						}
					} else {
						j := allJurisdictions[taskID%len(allJurisdictions)]
						diff, alert, err := svc.CheckJurisdiction(ctx, j)
						if err != nil {
							atomic.AddInt64(&droppedChecks, 1)
						} else {
							atomic.AddInt64(&completedChecks, 1)
							if alert != nil {
								atomic.AddInt64(&generatedAlertsCount, 1)
							}
							_ = diff
						}
					}
				}
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	// Grace period for asynchronous alert listener goroutines to complete
	time.Sleep(50 * time.Millisecond)

	runtime.ReadMemStats(&memAfter)

	recordedAlerts := svc.GetAlerts()

	// Assertions
	if droppedChecks != 0 {
		t.Fatalf("expected 0 dropped checks, got %d", droppedChecks)
	}
	if completedChecks != totalQueries {
		t.Fatalf("expected %d completed checks, got %d", totalQueries, completedChecks)
	}

	// Verify alert consistency
	if int(generatedAlertsCount) != len(recordedAlerts) {
		t.Errorf("mismatch between generated alerts count (%d) and recorded alerts (%d)",
			generatedAlertsCount, len(recordedAlerts))
	}
	if atomic.LoadInt64(&receivedAlertsCount) != int64(len(recordedAlerts)) {
		t.Errorf("mismatch between subscriber received alerts (%d) and recorded alerts (%d)",
			receivedAlertsCount, len(recordedAlerts))
	}

	reqsPerSec := float64(completedChecks) / duration.Seconds()
	avgLatency := duration / time.Duration(completedChecks)

	t.Logf("=== Concurrent Feed Scraper Storm Results ===")
	t.Logf("Workers: %d | Total Queries: %d | Completed: %d | Dropped: %d", numWorkers, totalQueries, completedChecks, droppedChecks)
	t.Logf("HTTP Feed Requests Processed: %d", atomic.LoadInt64(&httpReqCount))
	t.Logf("Generated Alerts: %d | Delivered to Listener: %d (100%% consistency)", len(recordedAlerts), receivedAlertsCount)
	t.Logf("Total Time: %v | Throughput: %.2f reqs/sec | Avg Latency/Query: %v", duration, reqsPerSec, avgLatency)
	t.Logf("Heap Alloc: %.2f MB | Heap In-Use: %.2f MB | Total GCs: %d",
		float64(memAfter.Alloc)/(1024*1024),
		float64(memAfter.HeapInuse)/(1024*1024),
		memAfter.NumGC-memBefore.NumGC)

	// Memory footprint verification: ensure heap footprint remains bounded (< 100MB)
	if memAfter.HeapInuse > 100*1024*1024 {
		t.Errorf("heap memory footprint exceeded 100MB limit: %.2f MB", float64(memAfter.HeapInuse)/(1024*1024))
	}
}

// BenchmarkScale_StatutoryDiffEngine benchmarks semantic diff computation across 1,000 sections.
func BenchmarkScale_StatutoryDiffEngine(b *testing.B) {
	diffEngine := NewDiffEngine()

	const count = 1000
	oldSections := make([]StatuteSection, 0, count)
	newSections := make([]StatuteSection, 0, count)

	for i := 0; i < count; i++ {
		oldSections = append(oldSections, StatuteSection{
			ID:      fmt.Sprintf("SEC-%04d", i),
			Title:   fmt.Sprintf("Statutory Title %d", i),
			Content: fmt.Sprintf("Baseline statutory requirement text content clause %d for automated decision tools.", i),
		})
	}

	for i := 0; i < count; i++ {
		content := fmt.Sprintf("Baseline statutory requirement text content clause %d for automated decision tools.", i)
		if i%5 == 0 { // 20% modified with breaking changes
			content = fmt.Sprintf("Baseline statutory requirement text content clause %d for automated decision tools, and must submit mandatory audit.", i)
		}
		newSections = append(newSections, StatuteSection{
			ID:      fmt.Sprintf("SEC-%04d", i),
			Title:   fmt.Sprintf("Statutory Title %d", i),
			Content: content,
		})
	}

	oldDoc := StatutoryDocument{
		Jurisdiction: JurisdictionColorado,
		Title:        "Colorado AI Act - Bench Baseline",
		Version:      "2026.1",
		Sections:     oldSections,
	}
	oldDoc.ComputeHash()

	newDoc := StatutoryDocument{
		Jurisdiction: JurisdictionColorado,
		Title:        "Colorado AI Act - Bench Revision",
		Version:      "2026.2",
		Sections:     newSections,
	}
	newDoc.ComputeHash()

	b.ReportAllocs()
	b.SetBytes(int64(count * 2)) // track processed sections
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = diffEngine.ComputeDiff(oldDoc, newDoc)
	}
}

// BenchmarkScale_ScraperIngestion benchmarks scraper document fetch and normalization.
func BenchmarkScale_ScraperIngestion(b *testing.B) {
	mockDoc := StatutoryDocument{
		Jurisdiction:  JurisdictionEU,
		Title:         "EU AI Office Regulation Stream",
		Version:       "2026.4",
		EffectiveDate: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC),
		Sections: []StatuteSection{
			{
				ID:      "Article-50",
				Title:   "Transparency Obligations",
				Content: "Providers shall ensure that AI systems intended to interact directly with natural persons are designed in such a way that natural persons are informed.",
			},
			{
				ID:      "Article-53",
				Title:   "Documentation for General-Purpose AI",
				Content: "Providers of general-purpose AI models shall draw up and keep up-to-date technical documentation of the model.",
			},
		},
	}
	mockDoc.ComputeHash()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockDoc)
	}))
	defer server.Close()

	cfg := ScraperConfig{
		ClientTimeoutSec: 5,
		CustomEndpoints: map[Jurisdiction]string{
			JurisdictionEU: server.URL,
		},
	}

	scraper := NewRegulatoryScraper(cfg, server.Client())
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := scraper.FetchJurisdictionDocument(ctx, JurisdictionEU)
		if err != nil {
			b.Fatalf("failed to fetch document: %v", err)
		}
	}
}
