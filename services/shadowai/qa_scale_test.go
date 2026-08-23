package shadowai

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestQA_ExtremeShadowAIScale_100KFiles stress-tests the detector across 100,000 enterprise files.
func TestQA_ExtremeShadowAIScale_100KFiles(t *testing.T) {
	const fileCount = 100_000
	t.Logf("=== Starting Extreme Scale Shadow AI Test: %d Files ===", fileCount)

	detector := NewShadowAIDetector()
	files := make([]FileEntry, fileCount)

	for i := 0; i < fileCount; i++ {
		path := fmt.Sprintf("src/pkg_%04d/module_%03d.go", i/100, i%100)
		var content string

		switch {
		case i%10 == 0:
			content = "OPENAI_KEY = 'sk-proj-9928172635481928374650192837465'"
		case i%15 == 0:
			content = "anthropicKey := 'sk-ant-api03-abcdef1234567890abcdef123456'"
		case i%20 == 0:
			path = fmt.Sprintf("services/srv_%d/.cursorrules", i)
			content = "Rule definitions"
		default:
			content = "package main\n\nfunc ProcessData() { /* regular business logic */ }\n"
		}

		files[i] = FileEntry{Path: path, Content: content}
	}

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	inv, err := detector.ScanFiles(files, DetectorOptions{OrganizationID: "org_scale_shadow"})
	duration := time.Since(start)

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	if err != nil {
		t.Fatalf("scale scan failed: %v", err)
	}

	filesPerSec := float64(fileCount) / duration.Seconds()
	findingsPerSec := float64(inv.TotalDiscovered) / duration.Seconds()

	t.Logf("=== Scale Shadow AI Results ===")
	t.Logf("Files Scanned: %d | Total Discoveries: %d (Critical: %d, High: %d)",
		fileCount, inv.TotalDiscovered, inv.CriticalCount, inv.HighCount)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f files/sec (%.2f findings/sec)", filesPerSec, findingsPerSec)
	t.Logf("Heap Alloc Delta: %.2f KB", float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/1024.0)

	if duration >= 10*time.Second {
		t.Fatalf("Performance violation: 100K file scan took %v (threshold: < 10.0s)", duration)
	}
}

// TestQA_ConcurrentShadowAIScan_100Workers tests concurrent scans with 100 goroutines.
func TestQA_ConcurrentShadowAIScan_100Workers(t *testing.T) {
	const numWorkers = 100
	const scansPerWorker = 50
	const totalScans = numWorkers * scansPerWorker // 5,000 scans

	t.Logf("=== Starting Concurrent Shadow AI Scan Test: %d Workers, %d Total Scans ===", numWorkers, totalScans)

	detector := NewShadowAIDetector()
	batchFiles := []FileEntry{
		{Path: ".cursorrules", Content: "cursor config"},
		{Path: "src/llm.py", Content: "sk-proj-9928172635481928374650192837465"},
		{Path: "src/utils.go", Content: "package utils"},
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
			for i := 0; i < scansPerWorker; i++ {
				orgID := fmt.Sprintf("org_worker_%03d", workerID)
				inv, err := detector.ScanFiles(batchFiles, DetectorOptions{OrganizationID: orgID})
				if err != nil || inv == nil || inv.InventoryHash == "" {
					atomic.AddInt64(&failedCount, 1)
				} else {
					atomic.AddInt64(&completedCount, 1)
				}
			}
		}(w)
	}

	wg.Wait()
	duration := time.Since(start)
	throughput := float64(totalScans) / duration.Seconds()

	t.Logf("=== Concurrent Shadow AI Results ===")
	t.Logf("Scans Completed: %d | Failures: %d", completedCount, failedCount)
	t.Logf("Execution Time: %v (%.3f ms)", duration, float64(duration.Microseconds())/1000.0)
	t.Logf("Throughput: %.2f scans/sec", throughput)

	if failedCount > 0 {
		t.Fatalf("expected 0 scan failures, got %d", failedCount)
	}
	if completedCount != int64(totalScans) {
		t.Fatalf("expected %d completed scans, got %d", totalScans, completedCount)
	}
	if duration >= 10*time.Second {
		t.Fatalf("Performance violation: Concurrent scans took %v (threshold: < 10.0s)", duration)
	}
}

// BenchmarkScale_ShadowAIDetection benchmarks single file scanning speed.
func BenchmarkScale_ShadowAIDetection(b *testing.B) {
	detector := NewShadowAIDetector()
	files := []FileEntry{
		{Path: "src/config.env", Content: "OPENAI_KEY=sk-proj-9928172635481928374650192837465"},
		{Path: ".cursorrules", Content: "rules"},
		{Path: "src/main.go", Content: "package main"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = detector.ScanFiles(files, DetectorOptions{OrganizationID: "org_bench"})
	}
}
