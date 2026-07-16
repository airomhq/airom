package modelfile

import (
	"context"
	"math"
	"strconv"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// GGUF value type tags (the gguf_metadata_value_type enum). Only scalars and
// strings carry data we extract; arrays are walked to stay aligned but not
// captured.
const (
	ggufTypeUint8 uint32 = iota
	ggufTypeInt8
	ggufTypeUint16
	ggufTypeInt16
	ggufTypeUint32
	ggufTypeInt32
	ggufTypeFloat32
	ggufTypeBool
	ggufTypeString
	ggufTypeArray
	ggufTypeUint64
	ggufTypeInt64
	ggufTypeFloat64
)

// ggufMagic is the four-byte file signature at offset 0.
var ggufMagic = []byte("GGUF")

// GGUF detects GGUF model files (the llama.cpp weight container) by parsing
// their header metadata only — never the tensor data. It extracts the model
// architecture, parameter count, and a best-effort quantization label from
// the general.* metadata keys.
type GGUF struct{}

// NewGGUF constructs the GGUF detector.
func NewGGUF() *GGUF { return &GGUF{} }

// ID returns the stable detector identity.
func (*GGUF) ID() string { return "modelfile/gguf" }

// Version is the detector's behavior version.
func (*GGUF) Version() int { return 1 }

// Selector routes .gguf files whose header carries the GGUF magic.
func (*GGUF) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".gguf"},
		Magic:      []detect.Magic{{Offset: 0, Bytes: ggufMagic}},
		Need:       detect.NeedContent,
	}
}

// ggufInfo is the header-only summary extracted from a GGUF file.
type ggufInfo struct {
	version      uint32
	architecture string
	name         string
	quantVersion string
	fileType     int64
	haveFileType bool
	paramCount   int64
	haveParam    bool
	quantization string
}

// DetectFile parses the GGUF header and emits one whole-file finding. It
// never loads tensor data and never panics on hostile bytes: an
// unrecognizable or truncated file yields no finding and no error.
func (d *GGUF) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, nil //nolint:nilerr // an unreadable file is not a detector error; it degrades to no finding
	}
	info, ok := parseGGUF(content)
	if !ok {
		return nil, nil
	}

	model := &detect.ModelClaim{Format: "gguf"}
	if info.architecture != "" {
		model.Architecture = info.architecture
	}
	if info.haveParam {
		model.ParamCount = info.paramCount
	}
	if info.quantization != "" {
		model.Quantization = info.quantization
	}

	fields := map[string]string{"version": strconv.FormatUint(uint64(info.version), 10)}
	if info.architecture != "" {
		fields["architecture"] = info.architecture
	}
	if info.name != "" {
		fields["name"] = info.name
	}
	if info.quantVersion != "" {
		fields["quantization_version"] = info.quantVersion
	}
	if info.haveFileType {
		fields["file_type"] = strconv.FormatInt(info.fileType, 10)
	}
	if info.quantization != "" {
		fields["quantization"] = info.quantization
	}
	if info.haveParam {
		fields["parameter_count"] = strconv.FormatInt(info.paramCount, 10)
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
			Confidence: airom.Confidence(0.95),
			Fields:     fields,
		},
	}}, nil
}

// parseGGUF reads the magic, version, counts, and metadata key/value pairs of
// a GGUF header. It returns ok==false only when the input is not a GGUF file
// at all (bad magic or unreadable version); a valid magic with partially
// unparseable metadata still returns the fields gathered so far.
func parseGGUF(b []byte) (ggufInfo, bool) {
	c := cursor{b: b}
	magic, ok := c.take(4)
	if !ok || string(magic) != string(ggufMagic) {
		return ggufInfo{}, false
	}
	var info ggufInfo
	if info.version, ok = c.u32(); !ok {
		return ggufInfo{}, false
	}
	// v2 and v3 share this layout (64-bit counts). v1 used 32-bit counts and
	// is not produced by any current tooling; decline it rather than
	// misparse.
	if info.version != 2 && info.version != 3 {
		return ggufInfo{}, false
	}
	if _, ok = c.u64(); !ok { // tensor_count — not needed for header facts
		return info, true
	}
	kvCount, ok := c.u64()
	if !ok {
		return info, true
	}

	limit := kvCount
	if limit > maxGGUFKV {
		limit = maxGGUFKV
	}
	for i := uint64(0); i < limit; i++ {
		key, val, ok := readGGUFKV(&c)
		if !ok {
			break // truncated or hostile metadata; keep what we have
		}
		applyGGUFKV(&info, key, val)
	}

	if info.haveFileType {
		info.quantization = ggufFileTypeName(info.fileType)
	}
	return info, true
}

// ggufValue is a decoded scalar/string GGUF metadata value. Arrays decode to
// kind==ggufTypeArray with no captured payload.
type ggufValue struct {
	kind uint32
	str  string
	i    int64
	u    uint64
}

// readGGUFKV reads one metadata pair: a length-prefixed key, a uint32 value
// type tag, then the typed value.
func readGGUFKV(c *cursor) (string, ggufValue, bool) {
	klen, ok := c.u64()
	if !ok || klen > maxKeyLen {
		return "", ggufValue{}, false
	}
	kb, ok := c.take(klen)
	if !ok {
		return "", ggufValue{}, false
	}
	key := string(kb)
	vtype, ok := c.u32()
	if !ok {
		return "", ggufValue{}, false
	}
	val, ok := readGGUFValue(c, vtype)
	if !ok {
		return "", ggufValue{}, false
	}
	return key, val, true
}

// readGGUFValue decodes a single typed value, or walks past an array. It
// rejects nested arrays and unknown type tags (ok==false) rather than
// recursing or guessing.
func readGGUFValue(c *cursor, vtype uint32) (ggufValue, bool) {
	switch vtype {
	case ggufTypeUint8, ggufTypeBool:
		b, ok := c.take(1)
		if !ok {
			return ggufValue{}, false
		}
		return ggufValue{kind: vtype, u: uint64(b[0])}, true
	case ggufTypeInt8:
		b, ok := c.take(1)
		if !ok {
			return ggufValue{}, false
		}
		return ggufValue{kind: vtype, i: int64(int8(b[0]))}, true // #nosec G115 -- two's-complement reinterpretation of a GGUF INT8 value, intentional
	case ggufTypeUint16, ggufTypeInt16:
		if !c.skip(2) {
			return ggufValue{}, false
		}
		// 16-bit scalars are not among the keys we extract; align only.
		return ggufValue{kind: vtype}, true
	case ggufTypeUint32:
		v, ok := c.u32()
		if !ok {
			return ggufValue{}, false
		}
		return ggufValue{kind: vtype, u: uint64(v)}, true
	case ggufTypeInt32:
		v, ok := c.u32()
		if !ok {
			return ggufValue{}, false
		}
		return ggufValue{kind: vtype, i: int64(int32(v))}, true // #nosec G115 -- two's-complement reinterpretation of a GGUF INT32 value, intentional
	case ggufTypeFloat32:
		if !c.skip(4) {
			return ggufValue{}, false
		}
		return ggufValue{kind: vtype}, true
	case ggufTypeUint64:
		v, ok := c.u64()
		if !ok {
			return ggufValue{}, false
		}
		return ggufValue{kind: vtype, u: v}, true
	case ggufTypeInt64:
		v, ok := c.u64()
		if !ok {
			return ggufValue{}, false
		}
		return ggufValue{kind: vtype, i: int64(v)}, true // #nosec G115 -- two's-complement reinterpretation of a GGUF INT64 value, intentional
	case ggufTypeFloat64:
		if !c.skip(8) {
			return ggufValue{}, false
		}
		return ggufValue{kind: vtype}, true
	case ggufTypeString:
		slen, ok := c.u64()
		if !ok || slen > maxStringLen {
			return ggufValue{}, false
		}
		sb, ok := c.take(slen)
		if !ok {
			return ggufValue{}, false
		}
		return ggufValue{kind: vtype, str: string(sb)}, true
	case ggufTypeArray:
		if !walkGGUFArray(c) {
			return ggufValue{}, false
		}
		return ggufValue{kind: ggufTypeArray}, true
	default:
		return ggufValue{}, false
	}
}

// walkGGUFArray consumes a GGUF array value (uint32 element type, uint64
// count, then the elements) without capturing it. Nested arrays are rejected
// to bound recursion, and the element count is capped.
func walkGGUFArray(c *cursor) bool {
	elemType, ok := c.u32()
	if !ok || elemType == ggufTypeArray {
		return false
	}
	count, ok := c.u64()
	if !ok {
		return false
	}
	if count > maxGGUFArrayElems {
		return false
	}
	if sz, fixed := ggufScalarSize(elemType); fixed {
		// Fixed-width elements: bulk-skip with an overflow-safe product.
		// sz is one of {1,2,4,8} from ggufScalarSize, always small and positive.
		w := uint64(sz) // #nosec G115 -- sz is a fixed small positive width
		total := count * w
		if total/w != count { // multiplication overflowed
			return false
		}
		return c.skip(total)
	}
	if elemType != ggufTypeString {
		return false // unknown element type
	}
	for i := uint64(0); i < count; i++ {
		slen, ok := c.u64()
		if !ok || slen > maxStringLen {
			return false
		}
		if !c.skip(slen) {
			return false
		}
	}
	return true
}

// ggufScalarSize returns the byte width of a fixed-size GGUF scalar type.
func ggufScalarSize(t uint32) (int, bool) {
	switch t {
	case ggufTypeUint8, ggufTypeInt8, ggufTypeBool:
		return 1, true
	case ggufTypeUint16, ggufTypeInt16:
		return 2, true
	case ggufTypeUint32, ggufTypeInt32, ggufTypeFloat32:
		return 4, true
	case ggufTypeUint64, ggufTypeInt64, ggufTypeFloat64:
		return 8, true
	default:
		return 0, false
	}
}

// applyGGUFKV records the general.* metadata keys the detector cares about.
func applyGGUFKV(info *ggufInfo, key string, v ggufValue) {
	switch key {
	case "general.architecture":
		if v.kind == ggufTypeString {
			info.architecture = v.str
		}
	case "general.name":
		if v.kind == ggufTypeString {
			info.name = v.str
		}
	case "general.quantization_version":
		if n, ok := ggufAsInt(v); ok {
			info.quantVersion = strconv.FormatInt(n, 10)
		}
	case "general.file_type":
		if n, ok := ggufAsInt(v); ok {
			info.fileType = n
			info.haveFileType = true
		}
	case "general.parameter_count":
		if n, ok := ggufAsInt(v); ok {
			info.paramCount = n
			info.haveParam = true
		}
	}
}

// ggufAsInt coerces an integer-typed GGUF value to int64, saturating an
// unsigned value that would overflow.
func ggufAsInt(v ggufValue) (int64, bool) {
	switch v.kind {
	case ggufTypeUint8, ggufTypeUint16, ggufTypeUint32, ggufTypeUint64, ggufTypeBool:
		if v.u > math.MaxInt64 {
			return math.MaxInt64, true
		}
		return int64(v.u), true
	case ggufTypeInt8, ggufTypeInt16, ggufTypeInt32, ggufTypeInt64:
		return v.i, true
	default:
		return 0, false
	}
}

// ggufFileTypeName maps the llama.cpp general.file_type enum to a
// quantization label. Unknown values fall back to a stable "ftype_N" form so
// the label is always deterministic.
func ggufFileTypeName(ft int64) string {
	if name, ok := ggufFileTypes[ft]; ok {
		return name
	}
	return "ftype_" + strconv.FormatInt(ft, 10)
}

// ggufFileTypes covers the common llama_ftype values (llama.cpp).
var ggufFileTypes = map[int64]string{
	0:  "F32",
	1:  "F16",
	2:  "Q4_0",
	3:  "Q4_1",
	7:  "Q8_0",
	8:  "Q5_0",
	9:  "Q5_1",
	10: "Q2_K",
	11: "Q3_K_S",
	12: "Q3_K_M",
	13: "Q3_K_L",
	14: "Q4_K_S",
	15: "Q4_K_M",
	16: "Q5_K_S",
	17: "Q5_K_M",
	18: "Q6_K",
	19: "IQ2_XXS",
	20: "IQ2_XS",
	21: "Q2_K_S",
	22: "IQ3_XS",
	23: "IQ3_XXS",
	24: "IQ1_S",
	25: "IQ4_NL",
	26: "IQ3_S",
	27: "IQ3_M",
	28: "IQ2_S",
	29: "IQ2_M",
	30: "IQ4_XS",
	31: "IQ1_M",
	32: "BF16",
}
