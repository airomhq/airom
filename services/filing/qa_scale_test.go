package filing

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestQA_ExtremeCalendarScale_50KCalculations stress-tests the RenewalEngine across 50,000 enterprise organizations.
func TestQA_ExtremeCalendarScale_50KCalculations(t *testing.T) {
	const orgCount = 50_000
	t.Logf("=== Starting Extreme Scale Calendar Renewal Test: %d Organizations ===", orgCount)

	engine := NewRenewalEngine()
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	// Pre-generate mixed filing histories
	histories := make([]FilingHistoryMap, orgCount)
	mods := make([]SubstantialModMap, orgCount)

	for i := 0; i < orgCount; i++ {
		h := make(FilingHistoryMap)
		m := make(SubstantialModMap)

		offsetDays := (i * 17) % 400
		h[JurisdictionColorado] = now.AddDate(0, 0, -offsetDays)
		h[JurisdictionCalifornia] = now.AddDate(0, 0, -(offsetDays + 10))
		h[JurisdictionNYC] = now.AddDate(0, 0, -(offsetDays + 20))
		h[JurisdictionEU] = now.AddDate(0, 0, -(offsetDays + 30))

		if i%5 == 0 {
			m[JurisdictionColorado] = now.AddDate(0, 0, -80)
		}

		histories[i] = h
		mods[i] = m
	}

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	var totalItemsEvaluated int64

	for i := 0; i < orgCount; i++ {
		orgID := fmt.Sprintf("org_scale_%06d", i)
		cal := engine.ComputeCalendar(orgID, histories[i], mods[i], now)
		totalItemsEvaluated += int64(len(cal.Items))
	}

	duration := time.Since(start)
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	orgsPerSec := float64(orgCount) / duration.Seconds()
	itemsPerSec := float64(totalItemsEvaluated) / duration.Seconds()

	t.Logf("=== Scale Calendar Results ===")
	t.Logf("Organizations Evaluated: %d | Schedule Items: %d", orgCount, totalItemsEvaluated)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f orgs/sec (%.2f items/sec)", orgsPerSec, itemsPerSec)
	t.Logf("Heap Alloc Delta: %.2f KB", float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/1024.0)

	// Assert sub-5s execution ceiling under CI and race detector
	if duration >= 5*time.Second {
		t.Fatalf("Performance violation: 50K calendar calculations took %v (threshold: < 5.0s)", duration)
	}
}

// TestQA_ConcurrentPackageGeneration_100Workers tests concurrent filing package assembly under 100 goroutines.
func TestQA_ConcurrentPackageGeneration_100Workers(t *testing.T) {
	const numWorkers = 100
	const packagesPerWorker = 50
	const totalPackages = numWorkers * packagesPerWorker // 5,000 packages

	t.Logf("=== Starting Concurrent Package Assembly Test: %d Workers, %d Total Packages ===", numWorkers, totalPackages)

	builder := NewPackageBuilder()
	jurisdictions := []Jurisdiction{
		JurisdictionColorado,
		JurisdictionCalifornia,
		JurisdictionNYC,
		JurisdictionEU,
		JurisdictionIllinois,
		JurisdictionTexas,
		JurisdictionVirginia,
	}

	var (
		completedCount int64
		failedCount    int64
		wg             sync.WaitGroup
	)

	start := time.Now()

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < packagesPerWorker; i++ {
				j := jurisdictions[(workerID+i)%len(jurisdictions)]
				opts := BuildPackageOptions{
					Jurisdiction:     j,
					OrganizationID:   fmt.Sprintf("org_worker_%03d", workerID),
					OrganizationName: fmt.Sprintf("Worker Corp %03d", workerID),
					RepositoryID:     fmt.Sprintf("repo_service_%d", i),
					SnapshotID:       fmt.Sprintf("snap_%d_%d", workerID, i),
					SignerName:       "Compliance Agent",
					SignerEmail:      "agent@airom.internal",
					ModelIDs:         []string{"gpt-4o", "claude-3-5-sonnet"},
					ControlsMetCount: 20,
					ControlsGapCount: 0,
				}

				manifest, err := builder.BuildPackage(opts)
				if err != nil || manifest == nil || manifest.PackageChecksum == "" {
					atomic.AddInt64(&failedCount, 1)
				} else {
					atomic.AddInt64(&completedCount, 1)
				}
			}
		}(w)
	}

	wg.Wait()
	duration := time.Since(start)
	throughput := float64(totalPackages) / duration.Seconds()

	t.Logf("=== Concurrent Package Assembly Results ===")
	t.Logf("Packages Completed: %d | Failures: %d", completedCount, failedCount)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f packages/sec", throughput)

	if failedCount > 0 {
		t.Fatalf("expected 0 package assembly failures, got %d", failedCount)
	}
	if completedCount != int64(totalPackages) {
		t.Fatalf("expected %d completed packages, got %d", totalPackages, completedCount)
	}
	if duration >= 10*time.Second {
		t.Fatalf("Performance violation: Concurrent package assembly took %v (threshold: < 10.0s)", duration)
	}
}

// BenchmarkScale_CalendarCalculation benchmarks single organization calendar computation.
func BenchmarkScale_CalendarCalculation(b *testing.B) {
	engine := NewRenewalEngine()
	now := time.Now().UTC()
	history := FilingHistoryMap{
		JurisdictionColorado:   now.AddDate(0, 0, -200),
		JurisdictionCalifornia: now.AddDate(0, 0, -100),
	}
	mods := SubstantialModMap{
		JurisdictionTexas: now.AddDate(0, 0, -30),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = engine.ComputeCalendar("org_bench", history, mods, now)
	}
}

// BenchmarkScale_PackageGeneration benchmarks Colorado SB 24-205 package assembly.
func BenchmarkScale_PackageGeneration(b *testing.B) {
	builder := NewPackageBuilder()
	opts := BuildPackageOptions{
		Jurisdiction:     JurisdictionColorado,
		OrganizationID:   "org_bench",
		OrganizationName: "Benchmark Corp",
		RepositoryID:     "repo_bench",
		SignerName:       "Bench Signer",
		SignerEmail:      "bench@airom.internal",
		ModelIDs:         []string{"gpt-4o"},
		ControlsMetCount: 15,
		ControlsGapCount: 0,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = builder.BuildPackage(opts)
	}
}
