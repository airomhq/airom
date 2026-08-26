package cockpit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeCockpitScale_50KRequests(t *testing.T) {
	srv := NewServer(CockpitConfig{})
	handler := srv.Routes()

	const numReqs = 50000
	req := httptest.NewRequest("GET", "/api/v1/state", nil)

	start := time.Now()
	for i := 0; i < numReqs; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	reqsPerSec := float64(numReqs) / duration.Seconds()
	t.Logf("=== SPRINT 112 SCALE: 50K COCKPIT API REQUESTS SERVED ===")
	t.Logf("Requests:   %d", numReqs)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f reqs/sec", reqsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentCockpitStorm_100Workers(t *testing.T) {
	srv := NewServer(CockpitConfig{})
	handler := srv.Routes()

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/api/v1/state", nil)
			for j := 0; j < iterations; j++ {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					errCh <- fmt.Errorf("unexpected failure")
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrency error: %v", err)
	}

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 112 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkCockpit_StateEndpoint(b *testing.B) {
	srv := NewServer(CockpitConfig{})
	handler := srv.Routes()
	req := httptest.NewRequest("GET", "/api/v1/state", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}
