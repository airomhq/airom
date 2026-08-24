package bundle

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeAirGapScale_10KBundles(t *testing.T) {
	compiler := NewCompiler([]byte("scale-key"))
	payloads := map[string][]byte{
		"r.yaml": []byte("rules"),
		"p.wasm": []byte("wasm"),
	}

	const numBundles = 10000
	start := time.Now()

	for i := 0; i < numBundles; i++ {
		pkg := compiler.BuildBundle(fmt.Sprintf("b-%d", i), "1.0", payloads, 1, 1, 1)
		err := compiler.VerifyBundle(pkg)
		if err != nil {
			t.Fatalf("failed at iter %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	bundlesPerSec := float64(numBundles) / duration.Seconds()
	t.Logf("=== SPRINT 73 SCALE: 10K AIR-GAP BUNDLES COMPILED & VERIFIED ===")
	t.Logf("Bundles:    %d", numBundles)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f bundles/sec", bundlesPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentAirGapStorm_100Workers(t *testing.T) {
	compiler := NewCompiler([]byte("conc-key"))
	payloads := map[string][]byte{"file.dat": []byte("data")}

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				pkg := compiler.BuildBundle("b", "1.0", payloads, 1, 1, 1)
				if err := compiler.VerifyBundle(pkg); err != nil {
					errCh <- err
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
	t.Logf("=== SPRINT 73 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkAirGap_BuildAndVerifyBundle(b *testing.B) {
	compiler := NewCompiler([]byte("bench-key"))
	payloads := map[string][]byte{"bench.bin": []byte("benchmark payload bytes")}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkg := compiler.BuildBundle("b", "1.0", payloads, 1, 1, 1)
		_ = compiler.VerifyBundle(pkg)
	}
}
