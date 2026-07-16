package modelfile

import (
	"path/filepath"
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detectortest"
)

func TestSafetensorsContract(t *testing.T) {
	detectortest.Run(t, NewSafetensors(), detectortest.Fixtures{Dir: filepath.Join("testdata", "safetensors")})
}

func TestSafetensorsExtraction(t *testing.T) {
	findings := detectFixture(t, NewSafetensors(), filepath.Join("testdata", "safetensors", "model.safetensors"))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	m := findings[0].Claim.Model
	if m == nil {
		t.Fatal("model claim is nil")
	}
	if m.Format != "safetensors" {
		t.Errorf("format = %q, want safetensors", m.Format)
	}
	if m.ParamCount != 40 { // [4,8]=32 + [8]=8
		t.Errorf("paramCount = %d, want 40", m.ParamCount)
	}
	if m.Quantization != "F16" {
		t.Errorf("quantization = %q, want F16", m.Quantization)
	}
	if m.Architecture != "bert" {
		t.Errorf("architecture = %q, want bert (from __metadata__)", m.Architecture)
	}
	if findings[0].Occurrence.Confidence != 0.95 {
		t.Errorf("confidence = %v, want 0.95", findings[0].Occurrence.Confidence)
	}
	if got := findings[0].Occurrence.Fields["metadata.format"]; got != "pt" {
		t.Errorf("fields[metadata.format] = %q, want pt", got)
	}
}

func TestSafetensorsRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":            nil,
		"short-length":     {1, 2, 3},
		"zero-length":      le64(0),
		"length-past-eof":  le64(1000),
		"not-json":         append(le64(4), []byte("!!!!")...),
		"json-array":       append(le64(2), []byte("[]")...),
		"oversized-header": le64(uint64(maxSafetensorsHeader) + 1),
	}
	det := NewSafetensors()
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			findings := detectBytes(t, det, "x.safetensors", data)
			if len(findings) != 0 {
				t.Errorf("want no finding for %s, got %d", name, len(findings))
			}
		})
	}
}

func TestSafetensorsEmptyHeaderStillDetects(t *testing.T) {
	// A structurally valid but tensorless header is still a safetensors file.
	data := append(le64(2), []byte("{}")...)
	findings := detectBytes(t, NewSafetensors(), "x.safetensors", data)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding for empty object header, got %d", len(findings))
	}
	m := findings[0].Claim.Model
	if m.Format != "safetensors" {
		t.Errorf("format = %q, want safetensors", m.Format)
	}
	if m.ParamCount != 0 {
		t.Errorf("paramCount = %d, want 0", m.ParamCount)
	}
}

func TestSafetensorsDominantDtype(t *testing.T) {
	// Mixed precision: one big BF16 tensor outweighs a small F32 one.
	header := `{"big":{"dtype":"BF16","shape":[100],"data_offsets":[0,200]},` +
		`"small":{"dtype":"F32","shape":[2],"data_offsets":[200,208]}}`
	data := append(le64(uint64(len(header))), []byte(header)...)
	findings := detectBytes(t, NewSafetensors(), "x.safetensors", data)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if got := findings[0].Claim.Model.Quantization; got != "BF16" {
		t.Errorf("dominant dtype = %q, want BF16", got)
	}
	if got := findings[0].Claim.Model.ParamCount; got != 102 {
		t.Errorf("paramCount = %d, want 102", got)
	}
}

func TestProductShapeOverflow(t *testing.T) {
	if _, ok := productShape([]int64{1 << 40, 1 << 40}); ok {
		t.Error("productShape must report overflow for a huge shape")
	}
	if _, ok := productShape([]int64{-1}); ok {
		t.Error("productShape must reject a negative dimension")
	}
	if n, ok := productShape(nil); !ok || n != 1 {
		t.Errorf("productShape(scalar) = (%d,%v), want (1,true)", n, ok)
	}
	if n, ok := productShape([]int64{0, 5}); !ok || n != 0 {
		t.Errorf("productShape(zero dim) = (%d,%v), want (0,true)", n, ok)
	}
}
