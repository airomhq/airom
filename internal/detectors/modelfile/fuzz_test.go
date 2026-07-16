package modelfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// The fuzz targets assert the two invariants every binary parser here must
// hold over arbitrary bytes: it never panics, and it never runs unbounded.
// The go test harness fails a target on a panic automatically; the per-input
// work is bounded by the safety caps in shared.go, so each execution returns
// promptly. The valid fixtures seed the corpus so the mutator starts from a
// structurally meaningful base.

func FuzzGGUF(f *testing.F) {
	fuzzDetector(f, NewGGUF(), "x.gguf", filepath.Join("testdata", "gguf", "model.gguf"))
}

func FuzzSafetensors(f *testing.F) {
	fuzzDetector(f, NewSafetensors(), "x.safetensors", filepath.Join("testdata", "safetensors", "model.safetensors"))
}

func FuzzONNX(f *testing.F) {
	fuzzDetector(f, NewONNX(), "x.onnx", filepath.Join("testdata", "onnx", "model.onnx"))
}

func fuzzDetector(f *testing.F, det detect.FileDetector, name, seedPath string) {
	f.Helper()
	if seed, err := os.ReadFile(seedPath); err == nil { //nolint:gosec // test reads its own fixture
		f.Add(seed)
	}
	f.Add([]byte(nil))
	f.Add([]byte("GGUF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		file := newTestFile(name, data)
		findings, err := det.DetectFile(context.Background(), file)
		if err != nil {
			t.Fatalf("DetectFile returned an error on fuzz input (parsers must degrade, not error): %v", err)
		}
		// Any emitted finding must satisfy the basic output contract.
		for i, fd := range findings {
			if fd.Claim.Kind == "" || fd.Claim.Name == "" {
				t.Fatalf("finding[%d] has empty Kind/Name", i)
			}
			if c := fd.Occurrence.Confidence; c <= 0 || c > 1 {
				t.Fatalf("finding[%d] confidence %v outside (0,1]", i, c)
			}
		}
	})
}
