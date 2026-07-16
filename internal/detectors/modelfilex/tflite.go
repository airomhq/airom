package modelfilex

import (
	"context"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// tfliteMagic is the FlatBuffer file identifier at offset 4 of a .tflite model.
var tfliteMagic = []byte("TFL3")

// TFLite detects TensorFlow Lite / LiteRT flatbuffer models by their "TFL3"
// file identifier, which sits at offset 4 (after the 4-byte root-table offset).
type TFLite struct{}

// NewTFLite constructs the TFLite detector.
func NewTFLite() *TFLite { return &TFLite{} }

// ID is the stable detector identity / SARIF ruleId.
func (TFLite) ID() string { return "modelfilex/tflite" }

// Version participates in cache keys; bump on any behavior change.
func (TFLite) Version() int { return 1 }

// Selector gates on the .tflite extension AND the offset-4 identifier. NeedHeader
// is enough — the identifier lives in the first bytes.
func (TFLite) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".tflite"},
		Magic:      []detect.Magic{{Offset: 4, Bytes: tfliteMagic}},
		Need:       detect.NeedHeader,
	}
}

// DetectFile emits a whole-file finding. It re-verifies the identifier as a
// defensive self-check so directly-fed truncated inputs yield nothing.
func (TFLite) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	if !hasMagic(f.Header(), 4, tfliteMagic) {
		return nil, nil
	}
	return []detect.Finding{modelFileFinding(f.Base(), "tflite", 0.9)}, nil
}
