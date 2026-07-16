package modelfile

import (
	"context"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Protobuf wire types (low 3 bits of a field tag).
const (
	wireVarint  = 0
	wire64bit   = 1
	wireLen     = 2
	wireStart   = 3 // group start (deprecated)
	wireEnd     = 4 // group end (deprecated)
	wire32bit   = 5
	wireInvalid = 6
)

// ModelProto top-level field numbers we sniff for.
const (
	onnxFieldIRVersion       = 1 // int64
	onnxFieldProducerName    = 2 // string
	onnxFieldProducerVersion = 3 // string
	onnxFieldGraph           = 7 // message
)

// ONNX detects ONNX model files via a light, dependency-free protobuf sniff
// of the top-level ModelProto fields — ir_version, producer_name,
// producer_version, and the presence of a graph. It does not vendor a
// protobuf library and never descends into tensor initializers.
type ONNX struct{}

// NewONNX constructs the ONNX detector.
func NewONNX() *ONNX { return &ONNX{} }

// ID returns the stable detector identity.
func (*ONNX) ID() string { return "modelfile/onnx" }

// Version is the detector's behavior version.
func (*ONNX) Version() int { return 1 }

// Selector routes .onnx files.
func (*ONNX) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".onnx"},
		Need:       detect.NeedContent,
	}
}

// onnxInfo is the summary of a top-level ModelProto sniff.
type onnxInfo struct {
	haveIRVersion   bool
	irVersion       int64
	producerName    string
	producerVersion string
	graphSeen       bool
}

// confirmed reports whether the sniff saw enough to call the file ONNX. A
// bare varint field is weak on its own, so a producer name (or an ir_version
// backed by a graph) is required.
func (i onnxInfo) confirmed() bool {
	return i.producerName != "" || i.haveIRVersion
}

// DetectFile sniffs the ONNX header and emits one whole-file finding, or
// nothing if the bytes do not decode as a ModelProto. The protobuf walk is
// iteration-capped and varint-safe: no truncation can panic it.
func (d *ONNX) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, nil //nolint:nilerr // unreadable file degrades to no finding, not an error
	}
	info := sniffONNX(content)
	if !info.confirmed() {
		return nil, nil // a .onnx that is not actually a ModelProto
	}

	model := &detect.ModelClaim{Format: "onnx"}
	if arch := onnxArchitecture(info.producerName); arch != "" {
		model.Architecture = arch
	}

	fields := map[string]string{}
	if info.haveIRVersion {
		fields["ir_version"] = strconv.FormatInt(info.irVersion, 10)
	}
	if info.producerName != "" {
		fields["producer_name"] = info.producerName
	}
	if info.producerVersion != "" {
		fields["producer_version"] = info.producerVersion
	}
	if info.graphSeen {
		fields["graph"] = "true"
	}
	if len(fields) == 0 {
		fields = nil
	}

	return []detect.Finding{{
		Claim: detect.ComponentClaim{
			Kind:     airom.KindLocalModelFile,
			Name:     f.Base(),
			Provider: "local",
			Model:    model,
		},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{}, // whole file; engine fills Path and SHA-256
			Method:     airom.MethodBinary,
			Confidence: airom.Confidence(0.9),
			Fields:     fields,
		},
	}}, nil
}

// sniffONNX walks the top-level protobuf fields of a ModelProto, capturing
// the handful that identify an ONNX file. Unknown fields are skipped by wire
// type; a malformed tag or length ends the walk.
func sniffONNX(b []byte) onnxInfo {
	c := cursor{b: b}
	var info onnxInfo
	for i := 0; i < maxProtobufFields && c.rem() > 0; i++ {
		tag, ok := c.uvarint()
		if !ok {
			break
		}
		field := tag >> 3
		wire := tag & 7
		switch wire {
		case wireVarint:
			v, ok := c.uvarint()
			if !ok {
				return info
			}
			if field == onnxFieldIRVersion {
				info.haveIRVersion = true
				info.irVersion = int64(v) // #nosec G115 -- ONNX ir_version is a protobuf int64; reinterpretation is intentional
			}
		case wire64bit:
			if !c.skip(8) {
				return info
			}
		case wireLen:
			n, ok := c.uvarint()
			if !ok {
				return info
			}
			payload, ok := c.take(n)
			if !ok {
				return info
			}
			applyONNXLenField(&info, field, payload)
		case wire32bit:
			if !c.skip(4) {
				return info
			}
		case wireStart, wireEnd, wireInvalid:
			return info // groups are deprecated; treat as end of a clean walk
		default:
			return info
		}
	}
	return info
}

// applyONNXLenField records a length-delimited top-level field: the producer
// strings (kept only if valid UTF-8) and the presence of a graph message.
func applyONNXLenField(info *onnxInfo, field uint64, payload []byte) {
	switch field {
	case onnxFieldProducerName:
		if utf8.Valid(payload) {
			info.producerName = string(payload)
		}
	case onnxFieldProducerVersion:
		if utf8.Valid(payload) {
			info.producerVersion = string(payload)
		}
	case onnxFieldGraph:
		info.graphSeen = true
	}
}

// onnxArchitecture derives a meaningful architecture label from a producer
// name, trimming whitespace and control bytes. An empty or non-printable
// producer name yields no label.
func onnxArchitecture(producer string) string {
	arch := strings.TrimSpace(producer)
	if arch == "" || !utf8.ValidString(arch) {
		return ""
	}
	for _, r := range arch {
		if r < 0x20 { // reject embedded control characters
			return ""
		}
	}
	return arch
}
