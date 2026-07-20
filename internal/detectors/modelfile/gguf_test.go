package modelfile

import (
	"context"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
	"github.com/airomhq/airom/pkg/airom/detectortest"
)

func TestGGUFContract(t *testing.T) {
	detectortest.Run(t, NewGGUF(), detectortest.Fixtures{Dir: filepath.Join("testdata", "gguf")})
}

func TestGGUFExtraction(t *testing.T) {
	findings := detectFixture(t, NewGGUF(), filepath.Join("testdata", "gguf", "model.gguf"))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Claim.Kind != airom.KindLocalModelFile {
		t.Errorf("kind = %q, want %q", f.Claim.Kind, airom.KindLocalModelFile)
	}
	if f.Claim.Name != "model.gguf" {
		t.Errorf("name = %q, want model.gguf", f.Claim.Name)
	}
	if f.Claim.Provider != "local" {
		t.Errorf("provider = %q, want local", f.Claim.Provider)
	}
	m := f.Claim.Model
	if m == nil {
		t.Fatal("model claim is nil")
	}
	if m.Format != "gguf" {
		t.Errorf("format = %q, want gguf", m.Format)
	}
	if m.Architecture != "llama" {
		t.Errorf("architecture = %q, want llama", m.Architecture)
	}
	if m.ParamCount != 1234 {
		t.Errorf("paramCount = %d, want 1234", m.ParamCount)
	}
	if m.Quantization != "F16" {
		t.Errorf("quantization = %q, want F16 (file_type 1)", m.Quantization)
	}
	if f.Occurrence.Method != airom.MethodBinary {
		t.Errorf("method = %q, want binary-analysis", f.Occurrence.Method)
	}
	if f.Occurrence.Confidence != 0.95 {
		t.Errorf("confidence = %v, want 0.95", f.Occurrence.Confidence)
	}
	if got := f.Occurrence.Fields["name"]; got != "tinyllama-test" {
		t.Errorf("fields[name] = %q, want tinyllama-test", got)
	}
	if got := f.Occurrence.Fields["quantization_version"]; got != "2" {
		t.Errorf("fields[quantization_version] = %q, want 2", got)
	}
	if len(f.Claim.Hashes) != 0 {
		t.Errorf("detector must leave Hashes empty; got %d", len(f.Claim.Hashes))
	}
	if f.Occurrence.Location != (airom.Location{}) {
		t.Errorf("location must be whole-file zero value, got %+v", f.Occurrence.Location)
	}
}

func TestGGUFRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":       nil,
		"short-magic": []byte("GG"),
		"bad-magic":   append([]byte("XXXX"), make([]byte, 32)...),
		"magic-only":  []byte("GGUF"), // magic but no version -> not confirmed
		"bad-version": ggufHeaderBytes(t, 1, 0, 0),
		"version-99":  ggufHeaderBytes(t, 99, 0, 0),
	}
	det := NewGGUF()
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			findings := detectBytes(t, det, "x.gguf", data)
			if len(findings) != 0 {
				t.Errorf("want no finding for %s, got %d", name, len(findings))
			}
		})
	}
}

func TestGGUFTruncatedAfterVersionStillDetects(t *testing.T) {
	// Valid magic + supported version already identify the file as GGUF, even
	// if the metadata table is truncated away.
	data := append([]byte("GGUF"), le32(3)...)
	findings := detectBytes(t, NewGGUF(), "x.gguf", data)
	if len(findings) != 1 {
		t.Fatalf("want 1 minimal finding, got %d", len(findings))
	}
	m := findings[0].Claim.Model
	if m.Format != "gguf" {
		t.Errorf("format = %q, want gguf", m.Format)
	}
	if m.Architecture != "" {
		t.Errorf("architecture = %q, want empty (no metadata parsed)", m.Architecture)
	}
}

func TestGGUFHostileKVCountDoesNotHang(t *testing.T) {
	// A declared kv_count of MaxUint64 must be capped, not looped over.
	var b []byte
	b = append(b, "GGUF"...)
	b = append(b, le32(3)...)                // version
	b = append(b, le64(0)...)                // tensor_count
	b = append(b, le64(^uint64(0))...)       // kv_count = 2^64-1
	b = append(b, le64(20)...)               // first key length
	b = append(b, "general.architecture"...) // key (20 bytes)
	b = append(b, le32(ggufTypeString)...)   // value type string
	b = append(b, le64(4)...)                // value length
	b = append(b, "gpt2"...)                 // value
	findings := detectBytes(t, NewGGUF(), "x.gguf", b)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding despite hostile kv_count, got %d", len(findings))
	}
	if got := findings[0].Claim.Model.Architecture; got != "gpt2" {
		t.Errorf("architecture = %q, want gpt2", got)
	}
}

func TestGGUFAllValueTypes(t *testing.T) {
	f32 := math.Float32bits(1.5)
	f64 := math.Float64bits(2.5)
	kvs := []ggufKV{
		{"a.u8", ggufTypeUint8, []byte{0x07}},
		{"a.i8", ggufTypeInt8, []byte{0xFF}}, // -1
		{"a.u16", ggufTypeUint16, le16(300)},
		{"a.i16", ggufTypeInt16, le16(0xFFFF)},
		{"a.u32", ggufTypeUint32, le32(5)},
		{"a.i32", ggufTypeInt32, le32(0xFFFFFFFF)}, // -1
		{"a.f32", ggufTypeFloat32, le32(f32)},
		{"a.bool", ggufTypeBool, []byte{0x01}},
		{"general.parameter_count", ggufTypeUint64, le64(999)},
		{"a.i64", ggufTypeInt64, le64(^uint64(0))}, // -1
		{"a.f64", ggufTypeFloat64, le64(f64)},
		{"general.architecture", ggufTypeString, ggufStr("gpt2")},
		{"a.arr_u32", ggufTypeArray, append(append(le32(ggufTypeUint32), le64(2)...), append(le32(1), le32(2)...)...)},
		{"a.arr_str", ggufTypeArray, append(append(le32(ggufTypeString), le64(1)...), ggufStr("x")...)},
		{"general.file_type", ggufTypeUint32, le32(7)}, // Q8_0
	}
	findings := detectBytes(t, NewGGUF(), "x.gguf", buildGGUF(kvs))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	m := findings[0].Claim.Model
	if m.Architecture != "gpt2" {
		t.Errorf("architecture = %q, want gpt2", m.Architecture)
	}
	if m.ParamCount != 999 {
		t.Errorf("paramCount = %d, want 999", m.ParamCount)
	}
	if m.Quantization != "Q8_0" {
		t.Errorf("quantization = %q, want Q8_0", m.Quantization)
	}
}

func TestGGUFStopsOnBadValueType(t *testing.T) {
	// An unknown value type ends metadata parsing but the file is still GGUF;
	// keys read before it survive.
	kvs := []ggufKV{
		{"general.architecture", ggufTypeString, ggufStr("mistral")},
		{"broken", 99, []byte{0x00}}, // unknown type -> parse stops here
		{"general.name", ggufTypeString, ggufStr("never-read")},
	}
	findings := detectBytes(t, NewGGUF(), "x.gguf", buildGGUF(kvs))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if got := findings[0].Claim.Model.Architecture; got != "mistral" {
		t.Errorf("architecture = %q, want mistral", got)
	}
	if got := findings[0].Occurrence.Fields["name"]; got != "" {
		t.Errorf("fields[name] = %q, want empty (parse stopped before it)", got)
	}
}

func TestGGUFRejectsNestedArray(t *testing.T) {
	// An array whose element type is itself an array must not recurse.
	nested := append(le32(ggufTypeArray), le64(1)...)
	kvs := []ggufKV{
		{"general.architecture", ggufTypeString, ggufStr("llama")},
		{"a.nested", ggufTypeArray, nested},
	}
	findings := detectBytes(t, NewGGUF(), "x.gguf", buildGGUF(kvs))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	// Architecture read before the nested array is retained.
	if got := findings[0].Claim.Model.Architecture; got != "llama" {
		t.Errorf("architecture = %q, want llama", got)
	}
}

// TestGGUFChatTemplateRisk: a chat_template carrying Jinja sandbox-escape
// gadgets flags AIROM-RISK-GGUF-TEMPLATE with the matched tokens; a normal
// template flags nothing.
func TestGGUFChatTemplateRisk(t *testing.T) {
	evil := `{% for m in messages %}{{ cycler.__init__.__globals__.os.popen('id').read() }}{% endfor %}`
	kvs := []ggufKV{
		{"general.architecture", ggufTypeString, ggufStr("llama")},
		{"tokenizer.chat_template", ggufTypeString, ggufStr(evil)},
	}
	findings := detectBytes(t, NewGGUF(), "x.gguf", buildGGUF(kvs))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	risks := findings[0].Claim.Risks
	if len(risks) != 1 || risks[0].ID != airom.RiskGGUFTemplate {
		t.Fatalf("Risks = %+v, want one gguf-template", risks)
	}
	// Detail names the dunder + os call the escape routes through (the `cycler`
	// pivot object is intentionally not a gadget), sorted & deduped.
	want := map[string]bool{"__globals__": true, "os.popen": true}
	if len(risks[0].Detail) != len(want) {
		t.Fatalf("detail = %v, want the two gadgets", risks[0].Detail)
	}
	for _, d := range risks[0].Detail {
		if !want[d] {
			t.Errorf("unexpected gadget %q in detail %v", d, risks[0].Detail)
		}
	}

	// Benign templates — including one using Jinja namespace() for loop state,
	// exactly as real Llama/Mistral templates do — must flag nothing.
	for _, benign := range []string{
		`{% for m in messages %}{{ m.role }}: {{ m.content }}{% endfor %}{{ eos_token }}`,
		`{% set ns = namespace(found=false) %}{% for m in messages %}{{ m.content | trim }}{% endfor %}`,
	} {
		kvs[1] = ggufKV{"tokenizer.chat_template", ggufTypeString, ggufStr(benign)}
		findings = detectBytes(t, NewGGUF(), "ok.gguf", buildGGUF(kvs))
		if len(findings) != 1 || len(findings[0].Claim.Risks) != 0 {
			t.Errorf("benign chat_template flagged a risk: %+v\n  template: %s", findings, benign)
		}
	}
}

type ggufKV struct {
	key     string
	vtype   uint32
	payload []byte
}

func buildGGUF(kvs []ggufKV) []byte {
	b := []byte("GGUF")
	b = append(b, le32(3)...) // v3 layout (v2 shares it; the detector accepts both)
	b = append(b, le64(0)...) // tensor_count
	b = append(b, le64(uint64(len(kvs)))...)
	for _, kv := range kvs {
		b = append(b, le64(uint64(len(kv.key)))...)
		b = append(b, kv.key...)
		b = append(b, le32(kv.vtype)...)
		b = append(b, kv.payload...)
	}
	return b
}

func ggufStr(s string) []byte { return append(le64(uint64(len(s))), s...) }

func le16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

// ggufHeaderBytes builds a bare GGUF header (magic+version+counts) with no KVs.
func ggufHeaderBytes(t *testing.T, version uint32, tensors, kv uint64) []byte {
	t.Helper()
	b := []byte("GGUF")
	b = append(b, le32(version)...)
	b = append(b, le64(tensors)...)
	b = append(b, le64(kv)...)
	return b
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// ── shared test helpers ───────────────────────────────────────────────────────

func detectFixture(t *testing.T, det detect.FileDetector, path string) []detect.Finding {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test reads its own fixture
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return detectBytes(t, det, filepath.Base(path), data)
}

func detectBytes(t *testing.T, det detect.FileDetector, name string, data []byte) []detect.Finding {
	t.Helper()
	f := newTestFile(name, data)
	findings, err := det.DetectFile(context.Background(), f)
	if err != nil {
		t.Fatalf("DetectFile(%s): unexpected error: %v", name, err)
	}
	return findings
}

func newTestFile(name string, data []byte) *detect.File {
	header := data
	if len(header) > 32*1024 {
		header = header[:32*1024]
	}
	ref := detect.FileRef{Path: name, Size: int64(len(data)), Language: detect.LanguageOf(name)}
	return detect.NewFile(ref, header, detect.FileProviders{
		Content: func() ([]byte, bool, error) { return data, false, nil },
	})
}
