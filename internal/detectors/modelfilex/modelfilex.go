// Package modelfilex implements binary "local model file" detectors for model
// serialization formats whose recognition needs more than a magic-byte gate:
// PyTorch archives (with a static, non-executing pickle opcode walk that flags
// dangerous imports), TensorFlow SavedModel protobufs, TFLite flatbuffers,
// Keras/HDF5 weight stores, and opaque TensorRT engines.
//
// It is a sibling of the internal/detectors/modelfile family and deliberately
// a separate package: these detectors carry parsing logic (zip, pickle,
// protobuf) that eats untrusted bytes, so every parser here returns errors
// instead of panicking and never allocates proportional to an
// attacker-controlled length field (docs/ARCHITECTURE.md §13).
package modelfilex

import (
	"bytes"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// modelFileFinding builds the whole-file KindLocalModelFile finding shared by
// the magic-gated detectors. The engine attaches the content SHA-256 and fills
// Location.Path/DetectorID, so the claim leaves Hashes empty and the
// occurrence uses a zero Location (Line 0 = whole file).
func modelFileFinding(name, format string, conf float64) detect.Finding {
	return detect.Finding{
		Claim: detect.ComponentClaim{
			Kind:     airom.KindLocalModelFile,
			Name:     name,
			Provider: "local",
			Model:    &detect.ModelClaim{Format: format},
		},
		Occurrence: airom.Occurrence{
			Method:     airom.MethodBinary,
			Confidence: airom.Confidence(conf),
		},
	}
}

// hasMagic reports whether header carries sig at the given offset. It is a
// defensive self-check: the selector already gated on the same signature, but
// re-verifying keeps each DetectFile self-consistent when the harness feeds it
// truncated bytes directly (bypassing selector routing).
func hasMagic(header []byte, offset int, sig []byte) bool {
	end := offset + len(sig)
	return offset >= 0 && end <= len(header) && bytes.Equal(header[offset:end], sig)
}
