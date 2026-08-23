package workforce

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestQA_ExtremeWorkforceScale_100KEmployees stress-tests workforce evaluation at massive scale (100,000 employees, 1,000 roles).
func TestQA_ExtremeWorkforceScale_100KEmployees(t *testing.T) {
	const roleCount = 1_000
	const headcountPerRole = 100
	const totalHeadcount = roleCount * headcountPerRole // 100,000 employees

	t.Logf("=== Starting Extreme Scale Workforce Assessment Test: %d Roles, %d Total Headcount ===", roleCount, totalHeadcount)

	engine := NewWorkforceEngine()

	capabilities := []AISystemCapability{
		{
			Name: "Enterprise Multimodal Agentic Cluster",
			AutomatedTasks: []string{
				"code-generation", "unit-testing", "customer-support-l1", "customer-support-l2",
				"invoice-processing", "financial-reconciliation", "legal-contract-review",
				"marketing-copywriting", "data-entry", "resume-screening", "meeting-summarization",
			},
			AutonomyLevel:       0.85,
			HighImpactDecisions: true,
		},
	}

	departments := []string{
		"Engineering", "Customer Success", "Finance", "Legal", "People Ops",
		"Marketing", "Sales", "Operations", "Product", "Security",
	}

	categories := []RoleCategory{
		RoleCategoryEngineering, RoleCategoryCustomerOps, RoleCategoryFinance,
		RoleCategoryLegal, RoleCategoryHR, RoleCategorySalesMktg, RoleCategoryGeneralOps,
	}

	roles := make([]RoleProfile, roleCount)
	for i := 0; i < roleCount; i++ {
		dept := departments[i%len(departments)]
		cat := categories[i%len(categories)]
		tasks := []string{
			fmt.Sprintf("task_%d_primary", i),
			fmt.Sprintf("task_%d_secondary", i),
			"meeting-summarization",
		}
		if i%3 == 0 {
			tasks = append(tasks, "code-generation", "unit-testing")
		}
		if i%4 == 0 {
			tasks = append(tasks, "customer-support-l1", "invoice-processing")
		}

		roles[i] = RoleProfile{
			RoleID:          fmt.Sprintf("role_%04d", i),
			Title:           fmt.Sprintf("Enterprise Specialist Tier %d", i),
			Category:        cat,
			Department:      dept,
			Headcount:       headcountPerRole,
			CoreTasks:       tasks,
			MedianSalaryUSD: 85000 + float64(i*50),
		}
	}

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	report, err := engine.AssessWorkforceImpact("org_enterprise_scale", "Frontier-AI-Stack", capabilities, roles, start)
	duration := time.Since(start)

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	if err != nil {
		t.Fatalf("scale assessment failed: %v", err)
	}

	rolesPerSec := float64(roleCount) / duration.Seconds()
	employeesPerSec := float64(totalHeadcount) / duration.Seconds()

	t.Logf("=== Scale Workforce Results ===")
	t.Logf("Roles Evaluated: %d | Headcount: %d | Displaced FTE: %.1f", roleCount, report.TotalHeadcount, report.AggregateDisplacedFTE)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f roles/sec (%.2f employees/sec)", rolesPerSec, employeesPerSec)
	t.Logf("Heap Alloc Delta: %.2f KB", float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/1024.0)

	if duration >= 5*time.Second {
		t.Fatalf("Performance violation: 100K employee assessment took %v (threshold: < 5.0s)", duration)
	}
}

// TestQA_ConcurrentWorkforceAssessments_100Workers tests concurrent workforce evaluations with 100 goroutines.
func TestQA_ConcurrentWorkforceAssessments_100Workers(t *testing.T) {
	const numWorkers = 100
	const assessmentsPerWorker = 50
	const totalAssessments = numWorkers * assessmentsPerWorker // 5,000 assessments

	t.Logf("=== Starting Concurrent Workforce Assessment Test: %d Workers, %d Total Assessments ===", numWorkers, totalAssessments)

	engine := NewWorkforceEngine()
	capabilities := []AISystemCapability{
		{
			Name:                "Coding Copilot",
			AutomatedTasks:      []string{"code-generation", "unit-testing"},
			AutonomyLevel:       0.8,
			HighImpactDecisions: false,
		},
	}

	roles := []RoleProfile{
		{
			RoleID:     "swe_01",
			Title:      "Software Engineer",
			Category:   RoleCategoryEngineering,
			Department: "Engineering",
			Headcount:  200,
			CoreTasks:  []string{"code-generation", "unit-testing", "architecture"},
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
			for i := 0; i < assessmentsPerWorker; i++ {
				orgID := fmt.Sprintf("org_worker_%03d", workerID)
				report, err := engine.AssessWorkforceImpact(orgID, "System-Copilot", capabilities, roles, time.Now().UTC())
				if err != nil || report == nil || report.ReportChecksum == "" {
					atomic.AddInt64(&failedCount, 1)
				} else {
					atomic.AddInt64(&completedCount, 1)
				}
			}
		}(w)
	}

	wg.Wait()
	duration := time.Since(start)
	throughput := float64(totalAssessments) / duration.Seconds()

	t.Logf("=== Concurrent Workforce Assessment Results ===")
	t.Logf("Assessments Completed: %d | Failures: %d", completedCount, failedCount)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f assessments/sec", throughput)

	if failedCount > 0 {
		t.Fatalf("expected 0 assessment failures, got %d", failedCount)
	}
	if completedCount != int64(totalAssessments) {
		t.Fatalf("expected %d completed assessments, got %d", totalAssessments, completedCount)
	}
	if duration >= 10*time.Second {
		t.Fatalf("Performance violation: Concurrent workforce assessment took %v (threshold: < 10.0s)", duration)
	}
}

// BenchmarkScale_WorkforceAssessment benchmarks single enterprise evaluation.
func BenchmarkScale_WorkforceAssessment(b *testing.B) {
	engine := NewWorkforceEngine()
	capabilities := []AISystemCapability{
		{
			Name:           "Copilot",
			AutomatedTasks: []string{"code-generation", "unit-testing"},
			AutonomyLevel:  0.8,
		},
	}
	roles := []RoleProfile{
		{
			RoleID:     "swe_01",
			Title:      "Software Engineer",
			Category:   RoleCategoryEngineering,
			Department: "Engineering",
			Headcount:  100,
			CoreTasks:  []string{"code-generation", "unit-testing", "architecture"},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = engine.AssessWorkforceImpact("org_bench", "System-Bench", capabilities, roles, time.Now().UTC())
	}
}
