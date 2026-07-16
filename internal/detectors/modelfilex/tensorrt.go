package modelfilex

import (
	"context"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// minEngineBytes is the smallest header we treat as a plausible engine — small
// enough not to reject a tiny real engine, large enough to reject empty stubs.
const minEngineBytes = 16

// TensorRT detects NVIDIA TensorRT serialized engines (.engine / .plan).
//
// HEURISTIC LIMITATION: a serialized TensorRT engine is an opaque,
// build-specific blob (tied to the exact TensorRT version, GPU architecture,
// and builder config) with no stable, publicly documented magic across
// releases. We therefore cannot parse or robustly fingerprint it. Detection is
// intentionally a low-confidence (0.7) heuristic: the .engine/.plan extension
// (from the selector) plus a binary-shape sanity check on the header — a real
// engine is a sizable binary blob, not a short ASCII text file that merely
// borrowed the extension. This can false-positive on unrelated binary blobs
// carrying these extensions; a precise parser would require reverse-engineering
// each TensorRT version's private header layout.
type TensorRT struct{}

// NewTensorRT constructs the TensorRT engine detector.
func NewTensorRT() *TensorRT { return &TensorRT{} }

// ID is the stable detector identity / SARIF ruleId.
func (TensorRT) ID() string { return "modelfilex/tensorrt" }

// Version participates in cache keys; bump on any behavior change.
func (TensorRT) Version() int { return 1 }

// Selector gates on the engine extensions. There is no magic dimension: the
// format has no stable signature (see the type comment). NeedHeader supplies
// the bytes the shape check inspects.
func (TensorRT) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".engine", ".plan"},
		Need:       detect.NeedHeader,
	}
}

// DetectFile applies the binary-shape heuristic and, on a pass, emits a
// low-confidence whole-file finding.
func (TensorRT) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	if !looksLikeTensorRTEngine(f.Header()) {
		return nil, nil
	}
	return []detect.Finding{modelFileFinding(f.Base(), "tensorrt", 0.7)}, nil
}

// looksLikeTensorRTEngine requires a non-trivial header that contains at least
// one clearly-binary byte (NUL, a high byte, or a non-whitespace control
// byte). This rejects text files that merely carry a .engine/.plan extension
// while accepting genuine binary engine blobs.
func looksLikeTensorRTEngine(header []byte) bool {
	if len(header) < minEngineBytes {
		return false
	}
	for _, b := range header {
		if b == 0 || b >= 0x80 {
			return true
		}
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			return true
		}
	}
	return false
}
