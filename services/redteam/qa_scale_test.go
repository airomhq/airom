package redteam

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestQA_ExtremeRedTeamScale_10KProbes stress-tests penetration evaluation across 10,000 probes.
func TestQA_ExtremeRedTeamScale_10KProbes(t *testing.T) {
	const assessmentCount = 2_000 // 2,000 assessments * 5 probes = 10,000 probes
	t.Logf("=== Starting Extreme Scale Red Team Test: %d Assessments (10,000 Probes) ===", assessmentCount)

	engine := NewRedTeamEngine()

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()

	for i := 0; i < assessmentCount; i++ {
		target := fmt.Sprintf("https://endpoint_%04d.internal/v1", i)
		model := fmt.Sprintf("model_tier_%d", i%10)
		assessment, err := engine.ExecuteAssessment(context.Background(), target, model, nil)
		if err != nil || assessment == nil || assessment.AssessmentChecksum == "" {
			t.Fatalf("assessment failed at index %d", i)
		}
	}

	duration := time.Since(start)
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	totalProbes := assessmentCount * len(engine.probes)
	probesPerSec := float64(totalProbes) / duration.Seconds()

	t.Logf("=== Scale Red Team Results ===")
	t.Logf("Assessments: %d | Total Probes Executed: %d", assessmentCount, totalProbes)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f probes/sec", probesPerSec)
	t.Logf("Heap Alloc Delta: %.2f KB", float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/1024.0)

	if duration >= 5*time.Second {
		t.Fatalf("Performance violation: 10K probes took %v (threshold: < 5.0s)", duration)
	}
}

// TestQA_ConcurrentRedTeamStorm_100Workers tests concurrent penetration assessments with 100 goroutines.
func TestQA_ConcurrentRedTeamStorm_100Workers(t *testing.T) {
	const numWorkers = 100
	const assessmentsPerWorker = 50
	const totalAssessments = numWorkers * assessmentsPerWorker // 5,000 assessments

	t.Logf("=== Starting Concurrent Red Team Test: %d Workers, %d Total Assessments ===", numWorkers, totalAssessments)

	engine := NewRedTeamEngine()

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
				target := fmt.Sprintf("https://worker_%03d.internal", workerID)
				a, err := engine.ExecuteAssessment(context.Background(), target, "gpt-4o", nil)
				if err != nil || a == nil || a.AssessmentChecksum == "" {
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

	t.Logf("=== Concurrent Red Team Results ===")
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
		t.Fatalf("Performance violation: Concurrent assessments took %v (threshold: < 10.0s)", duration)
	}
}

// BenchmarkScale_SecurityProbeExecution benchmarks single probe evaluation.
func BenchmarkScale_SecurityProbeExecution(b *testing.B) {
	engine := NewRedTeamEngine()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = engine.ExecuteAssessment(ctx, "https://api.target.internal", "model", nil)
	}
}
