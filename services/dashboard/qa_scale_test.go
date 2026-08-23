package dashboard

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestQA_ExtremeDashboardScale_1KOrgs stress-tests multi-org posture calculations across 1,000 enterprise subsidiaries.
func TestQA_ExtremeDashboardScale_1KOrgs(t *testing.T) {
	const orgCount = 1_000
	t.Logf("=== Starting Extreme Scale Dashboard Test: %d Organizations ===", orgCount)

	engine := NewDashboardEngine()
	sectors := []string{"Fintech", "Healthcare", "E-Commerce", "Logistics", "Aerospace", "Energy", "Telecom", "Media"}

	orgs := make([]OrganizationRollup, orgCount)
	for i := 0; i < orgCount; i++ {
		compScore := 60.0 + float64(i%40)
		critGaps := 0
		if compScore < 80.0 {
			critGaps = (100 - int(compScore)) / 5
		}

		orgs[i] = OrganizationRollup{
			OrganizationID:     fmt.Sprintf("org_%04d", i),
			OrganizationName:   fmt.Sprintf("Subsidiary Entity %d", i),
			Sector:             sectors[i%len(sectors)],
			RepositoryCount:    20 + (i % 50),
			TotalComponents:    100 + (i % 300),
			ComplianceScore:    compScore,
			CriticalGapsCount:  critGaps,
			ShadowAICount:      i % 5,
			DisplacedFTECount:  float64(i % 15),
			UrgentFilingsCount: i % 3,
			FrameworkCompliance: map[string]float64{
				"Colorado AI Act": compScore + 1.0,
				"EU AI Act":       compScore - 1.0,
			},
			LastAuditedAt: time.Now().UTC(),
		}
	}

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	matrix, err := engine.CalculateExecutivePosture(orgs)
	duration := time.Since(start)

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	if err != nil {
		t.Fatalf("scale calculation failed: %v", err)
	}

	orgsPerSec := float64(orgCount) / duration.Seconds()

	t.Logf("=== Scale Dashboard Results ===")
	t.Logf("Organizations Rolled Up: %d | Total AI Components: %d", orgCount, matrix.Summary.TotalAIComponents)
	t.Logf("Aggregate Compliance: %.2f%% | Overall Grade: [%s]", matrix.Summary.AggregateCompliance, matrix.Summary.OverallPostureGrade)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f orgs/sec", orgsPerSec)
	t.Logf("Heap Alloc Delta: %.2f KB", float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/1024.0)

	if duration >= 5*time.Second {
		t.Fatalf("Performance violation: 1K org posture calculation took %v (threshold: < 5.0s)", duration)
	}
}

// TestQA_ConcurrentDashboardCalculations_100Workers tests concurrent posture requests with 100 goroutines.
func TestQA_ConcurrentDashboardCalculations_100Workers(t *testing.T) {
	const numWorkers = 100
	const rollupsPerWorker = 50
	const totalRollups = numWorkers * rollupsPerWorker // 5,000 rollups

	t.Logf("=== Starting Concurrent Dashboard Test: %d Workers, %d Total Rollups ===", numWorkers, totalRollups)

	engine := NewDashboardEngine()
	sampleOrgs := []OrganizationRollup{
		{
			OrganizationID:    "org_sample",
			OrganizationName:  "Sample Org",
			ComplianceScore:   92.0,
			CriticalGapsCount: 0,
		},
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
			for i := 0; i < rollupsPerWorker; i++ {
				matrix, err := engine.CalculateExecutivePosture(sampleOrgs)
				if err != nil || matrix == nil || matrix.MatrixChecksum == "" {
					atomic.AddInt64(&failedCount, 1)
				} else {
					atomic.AddInt64(&completedCount, 1)
				}
			}
		}(w)
	}

	wg.Wait()
	duration := time.Since(start)
	throughput := float64(totalRollups) / duration.Seconds()

	t.Logf("=== Concurrent Dashboard Results ===")
	t.Logf("Rollups Completed: %d | Failures: %d", completedCount, failedCount)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f rollups/sec", throughput)

	if failedCount > 0 {
		t.Fatalf("expected 0 rollup failures, got %d", failedCount)
	}
	if completedCount != int64(totalRollups) {
		t.Fatalf("expected %d completed rollups, got %d", totalRollups, completedCount)
	}
	if duration >= 10*time.Second {
		t.Fatalf("Performance violation: Concurrent dashboard rollups took %v (threshold: < 10.0s)", duration)
	}
}

// BenchmarkScale_ExecutivePostureRollup benchmarks single posture calculation.
func BenchmarkScale_ExecutivePostureRollup(b *testing.B) {
	engine := NewDashboardEngine()
	orgs := []OrganizationRollup{
		{
			OrganizationID:   "org_bench",
			OrganizationName: "Bench Corp",
			ComplianceScore:  88.5,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = engine.CalculateExecutivePosture(orgs)
	}
}
