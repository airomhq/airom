package modelfilex

import (
	"context"
	"path"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// SavedModel detects a TensorFlow SavedModel, which on disk is a DIRECTORY
// (saved_model.pb + a variables/ subdir), not a single file. We anchor on the
// saved_model.pb protobuf and report the enclosing directory as the model's
// name, since that directory is the loadable unit.
type SavedModel struct{}

// NewSavedModel constructs the TensorFlow SavedModel detector.
func NewSavedModel() *SavedModel { return &SavedModel{} }

// ID is the stable detector identity / SARIF ruleId.
func (SavedModel) ID() string { return "modelfilex/savedmodel" }

// Version participates in cache keys; bump on any behavior change.
func (SavedModel) Version() int { return 1 }

// Selector anchors on the exact basename. NeedContent because we sniff the
// protobuf body to avoid claiming any unrelated file that happens to be named
// saved_model.pb.
func (SavedModel) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"saved_model.pb"},
		Need:      detect.NeedContent,
	}
}

// DetectFile confirms the protobuf shape, then emits a whole-file finding named
// after the parent directory.
func (SavedModel) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	if !looksLikeSavedModel(content) {
		return nil, nil
	}
	return []detect.Finding{{
		Claim: detect.ComponentClaim{
			Kind:     airom.KindLocalModelFile,
			Name:     savedModelName(f.Path()),
			Provider: "local",
			Model:    &detect.ModelClaim{Format: "tensorflow-savedmodel"},
		},
		Occurrence: airom.Occurrence{
			Method:     airom.MethodBinary,
			Confidence: airom.Confidence(0.9),
		},
	}}, nil
}

// savedModelName returns the enclosing directory name for a saved_model.pb
// path, falling back to the basename when the file has no meaningful parent.
func savedModelName(p string) string {
	dir := path.Dir(p)
	name := path.Base(dir)
	switch name {
	case ".", "/", "":
		return path.Base(p)
	default:
		return name
	}
}

// looksLikeSavedModel does a light protobuf field-presence walk over the
// SavedModel message shape:
//
//	message SavedModel {
//	  int64 saved_model_schema_version = 1;  // varint
//	  repeated MetaGraphDef meta_graphs = 2;  // length-delimited
//	}
//
// It confirms every top-level field is one of those two with the correct wire
// type and that meta_graphs (field 2) is present. It never parses inside a
// meta_graph, never allocates for a length field, and treats a length running
// past the (possibly header-truncated) buffer as "present, stop here".
func looksLikeSavedModel(buf []byte) bool {
	const maxFields = 32
	i, sawMetaGraph := 0, false
	for fields := 0; fields < maxFields && i < len(buf); fields++ {
		tag, ni, ok := readVarint(buf, i)
		if !ok {
			return false
		}
		i = ni
		fieldNum := tag >> 3
		wire := tag & 7

		switch fieldNum {
		case 1: // saved_model_schema_version — varint
			if wire != 0 {
				return false
			}
			_, ni, ok := readVarint(buf, i)
			if !ok {
				return false
			}
			i = ni
		case 2: // meta_graphs — length-delimited
			if wire != 2 {
				return false
			}
			length, ni, ok := readVarint(buf, i)
			if !ok {
				return false
			}
			i = ni
			sawMetaGraph = true
			rem := len(buf) - i       // >= 0 (i <= len(buf))
			if length > uint64(rem) { // #nosec G115 -- rem >= 0, so int->uint64 is exact
				return true // field 2 present with the right wire type; enough
			}
			i += int(length) // #nosec G115 -- length <= rem <= len(buf) < 2^31, fits int
		default:
			return false // any other top-level field ⇒ not a SavedModel
		}
	}
	return sawMetaGraph
}

// readVarint decodes a base-128 varint at i, reading at most the 10 bytes a
// 64-bit varint can occupy. ok is false on a truncated or over-long varint.
func readVarint(buf []byte, i int) (uint64, int, bool) {
	var val uint64
	var shift uint
	for n := 0; n < 10 && i < len(buf); n++ {
		b := buf[i]
		i++
		val |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return val, i, true
		}
		shift += 7
	}
	return 0, i, false
}
