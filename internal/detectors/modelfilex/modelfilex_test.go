package modelfilex

import (
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detect"
	"github.com/Roro1727/airom/pkg/airom/detectortest"
)

// Each detector is exercised through the public contract harness: golden
// findings, real-index selector gating (the decoy.txt fixtures must never
// reach DetectFile), 1-based locations, determinism, truncation robustness,
// and dir-backed == stream-backed output.

func TestTorch(t *testing.T) {
	detectortest.Run(t, NewTorch(), detectortest.Fixtures{Dir: "testdata/torch"})
}

func TestSavedModel(t *testing.T) {
	detectortest.Run(t, NewSavedModel(), detectortest.Fixtures{Dir: "testdata/savedmodel"})
}

func TestTFLite(t *testing.T) {
	detectortest.Run(t, NewTFLite(), detectortest.Fixtures{Dir: "testdata/tflite"})
}

func TestHDF5(t *testing.T) {
	detectortest.Run(t, NewHDF5(), detectortest.Fixtures{Dir: "testdata/hdf5"})
}

func TestTensorRT(t *testing.T) {
	detectortest.Run(t, NewTensorRT(), detectortest.Fixtures{Dir: "testdata/tensorrt"})
}

// TestConstructorsImplementFileDetector asserts every exported constructor
// returns a value the generator can register as a FileDetector.
func TestConstructorsImplementFileDetector(t *testing.T) {
	dets := []detect.Detector{
		NewTorch(), NewSavedModel(), NewTFLite(), NewHDF5(), NewTensorRT(),
	}
	for _, d := range dets {
		if _, ok := d.(detect.FileDetector); !ok {
			t.Errorf("%s: not a FileDetector", d.ID())
		}
		if d.ID() == "" {
			t.Error("empty detector ID")
		}
		if d.Version() < 1 {
			t.Errorf("%s: Version() = %d, want >= 1", d.ID(), d.Version())
		}
	}
}
