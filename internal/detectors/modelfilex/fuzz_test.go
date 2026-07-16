package modelfilex

import (
	"context"
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// FuzzTorchPickle drives the static pickle opcode walker with arbitrary bytes.
// Hostile pickle streams must never panic, hang, or over-allocate — the walker
// is the security boundary for weaponized checkpoints.
func FuzzTorchPickle(f *testing.F) {
	seeds := [][]byte{
		nil,
		{0x80, 0x02},
		append([]byte{'c'}, "os\nsystem\n."...),
		append([]byte{0x8c, 0x05}, "posix"...),
		{0x93}, // STACK_GLOBAL with empty stack
		{0x95, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x58, 0xff, 0xff, 0xff, 0xff},                         // BINUNICODE lying length
		{0x8d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // BINUNICODE8 lying length
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		globals := pickleGlobals(data)
		// The result must be usable and deterministic downstream.
		_ = suspiciousGlobals(globals)
	})
}

// FuzzTorchDetect drives the full torch DetectFile (zip + pickle paths) with
// arbitrary bytes prefixed by each recognized magic, plus the raw input.
func FuzzTorchDetect(f *testing.F) {
	f.Add([]byte("PK\x03\x04garbage"))
	f.Add([]byte{0x80, 0x02, 'c', '.'})
	f.Add([]byte("not a model"))
	det := Torch{}
	f.Fuzz(func(_ *testing.T, data []byte) {
		file := detect.NewFile(
			detect.FileRef{Path: "x.pt", Size: int64(len(data))},
			data,
			detect.FileProviders{Content: func() ([]byte, bool, error) { return data, false, nil }},
		)
		// Errors are acceptable (corrupt inputs); panics are not.
		_, _ = det.DetectFile(context.Background(), file)
	})
}

// FuzzSavedModel drives the protobuf field-presence sniff with arbitrary bytes.
func FuzzSavedModel(f *testing.F) {
	f.Add([]byte{0x08, 0x01, 0x12, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Add([]byte(nil))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = looksLikeSavedModel(data)
	})
}

// FuzzTensorRT drives the binary-shape heuristic with arbitrary bytes.
func FuzzTensorRT(f *testing.F) {
	f.Add([]byte("trt\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Add([]byte("plain text"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = looksLikeTensorRTEngine(data)
	})
}
