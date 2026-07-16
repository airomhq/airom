package modelfilex

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"path"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// zipMagic is the local-file-header signature every PyTorch zip archive opens
// with. pickleProto is the PROTO opcode a legacy (non-zip) torch pickle opens
// with.
var (
	zipMagic    = []byte{'P', 'K', 0x03, 0x04}
	pickleProto = byte(0x80)
)

// Torch detects PyTorch model files in both serialization forms and statically
// screens their embedded pickle for dangerous imports.
//
//   - Modern form: a zip archive (magic "PK\x03\x04") containing "*/data.pkl".
//   - Legacy form: a bare pickle stream (magic byte 0x80, the PROTO opcode).
//
// It emits a single whole-file KindLocalModelFile finding. The confidence is
// 0.9 normally and 0.95 when the pickle walk finds suspicious globals, because
// a smuggled os.system / subprocess.Popen is a strong, security-relevant
// signal that this really is a (weaponized) pickle.
type Torch struct{}

// NewTorch constructs the PyTorch detector.
func NewTorch() *Torch { return &Torch{} }

// ID is the stable detector identity / SARIF ruleId.
func (Torch) ID() string { return "modelfilex/torch" }

// Version participates in cache keys; bump on any behavior change.
func (Torch) Version() int { return 1 }

// Selector routes .pt/.pth/.bin files whose header is either a zip or a pickle
// PROTO. Need is NeedContent because both forms require reading the body (the
// zip central directory sits at the end of the file, and the legacy pickle is
// the whole file).
func (Torch) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".pt", ".pth", ".bin"},
		Magic: []detect.Magic{
			{Offset: 0, Bytes: zipMagic},
			{Offset: 0, Bytes: []byte{pickleProto}},
		},
		Need: detect.NeedContent,
	}
}

// DetectFile reads the file, picks the serialization form from the leading
// bytes, walks the pickle for globals, and emits the finding.
func (Torch) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, nil
	}

	var (
		format  string
		globals [][2]string
	)
	switch {
	case bytes.HasPrefix(content, zipMagic):
		format = "torch-zip"
		pkl, zerr := torchZipPickle(content)
		if zerr != nil {
			return nil, zerr
		}
		globals = pickleGlobals(pkl) // pkl may be nil (no data.pkl); that's fine
	case content[0] == pickleProto:
		format = "torch-pickle"
		globals = pickleGlobals(content)
	default:
		// Selector guarantees one of the above; be defensive on truncated
		// inputs fed directly by the harness.
		return nil, nil
	}

	model := &detect.ModelClaim{Format: format}
	conf := 0.9
	if risky := suspiciousGlobals(globals); len(risky) > 0 {
		model.PickleRisk = &airom.PickleRisk{Globals: risky}
		conf = 0.95
	}

	return []detect.Finding{{
		Claim: detect.ComponentClaim{
			Kind:     airom.KindLocalModelFile,
			Name:     f.Base(),
			Provider: "local",
			Model:    model,
		},
		Occurrence: airom.Occurrence{
			Method:     airom.MethodBinary,
			Confidence: airom.Confidence(conf),
		},
	}}, nil
}

// torchZipPickle opens the archive over the in-memory content (Content(), never
// ReaderAt — ReaderAt is nil on image/tar scans) and returns the bytes of the
// first "*/data.pkl" (or "data.pkl") entry. The decompressed read is capped by
// maxPickleBytes to bound zip-bomb exposure. A missing data.pkl returns nil,
// nil — still a valid torch-zip, just nothing to screen.
func torchZipPickle(content []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("modelfilex/torch: open zip: %w", err)
	}
	for _, zf := range zr.File {
		if path.Base(zf.Name) != "data.pkl" {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, fmt.Errorf("modelfilex/torch: open %q: %w", zf.Name, err)
		}
		data, rerr := io.ReadAll(io.LimitReader(rc, maxPickleBytes))
		cerr := rc.Close()
		if rerr != nil {
			return nil, fmt.Errorf("modelfilex/torch: read %q: %w", zf.Name, rerr)
		}
		if cerr != nil {
			return nil, fmt.Errorf("modelfilex/torch: close %q: %w", zf.Name, cerr)
		}
		return data, nil
	}
	return nil, nil
}
