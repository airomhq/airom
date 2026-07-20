package modelfilex

import (
	"context"

	"github.com/airomhq/airom/pkg/airom/detect"
)

// hdf5Magic is the 8-byte HDF5 superblock signature. Keras (legacy .h5/.keras)
// weight stores and many other Keras/TensorFlow artifacts are HDF5 containers.
var hdf5Magic = []byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'}

// HDF5 detects HDF5-backed model/weight files. Confidence is 0.85 because we
// confirm the container format but do not parse its internal structure (the
// group/dataset layout that would distinguish a Keras model from arbitrary
// HDF5 data).
type HDF5 struct{}

// NewHDF5 constructs the HDF5 detector.
func NewHDF5() *HDF5 { return &HDF5{} }

// ID is the stable detector identity / SARIF ruleId.
func (HDF5) ID() string { return "modelfilex/hdf5" }

// Version participates in cache keys; bump on any behavior change.
func (HDF5) Version() int { return 2 }

// Selector gates on the weight-store extensions AND the HDF5 superblock magic.
// A Keras 3 .keras file is actually a zip and will not carry this magic, so it
// is correctly not routed here. NeedContent (bounded by --max-file-size) lets
// the Lambda-layer scan see the model_config, which HDF5 stores near the file
// start but not always within the 32 KB header sample.
func (HDF5) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".h5", ".hdf5", ".keras"},
		Magic:      []detect.Magic{{Offset: 0, Bytes: hdf5Magic}},
		Need:       detect.NeedContent,
	}
}

// DetectFile emits a whole-file finding, re-verifying the magic defensively,
// and flags a Keras Lambda layer (arbitrary Python marshaled into the config)
// when the model_config declares one.
func (HDF5) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	if !hasMagic(f.Header(), 0, hdf5Magic) {
		return nil, nil
	}
	finding := modelFileFinding(f.Base(), "hdf5", 0.85)
	if content, err := f.Content(); err == nil {
		finding.Claim.Risks = kerasLambdaRisk(content)
	}
	return []detect.Finding{finding}, nil
}
