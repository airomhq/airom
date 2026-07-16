package modelfile

import (
	"path/filepath"
	"testing"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detectortest"
)

func TestONNXContract(t *testing.T) {
	detectortest.Run(t, NewONNX(), detectortest.Fixtures{Dir: filepath.Join("testdata", "onnx")})
}

func TestONNXExtraction(t *testing.T) {
	findings := detectFixture(t, NewONNX(), filepath.Join("testdata", "onnx", "model.onnx"))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	m := f.Claim.Model
	if m == nil {
		t.Fatal("model claim is nil")
	}
	if m.Format != "onnx" {
		t.Errorf("format = %q, want onnx", m.Format)
	}
	if m.Architecture != "airom-test" {
		t.Errorf("architecture = %q, want airom-test (producer_name)", m.Architecture)
	}
	if f.Occurrence.Method != airom.MethodBinary {
		t.Errorf("method = %q, want binary-analysis", f.Occurrence.Method)
	}
	if f.Occurrence.Confidence != 0.9 {
		t.Errorf("confidence = %v, want 0.9", f.Occurrence.Confidence)
	}
	if got := f.Occurrence.Fields["ir_version"]; got != "7" {
		t.Errorf("fields[ir_version] = %q, want 7", got)
	}
	if got := f.Occurrence.Fields["producer_version"]; got != "0.0.1" {
		t.Errorf("fields[producer_version] = %q, want 0.0.1", got)
	}
	if got := f.Occurrence.Fields["graph"]; got != "true" {
		t.Errorf("fields[graph] = %q, want true", got)
	}
}

func TestONNXRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":              nil,
		"all-continuation":   {0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		"only-unknown-field": {0x2A, 0x01, 0x00}, // field 5 (model_version-ish) varint, no id/name
		"truncated-len":      {0x12, 0x7F},       // producer_name with length 127 but no bytes
	}
	det := NewONNX()
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			findings := detectBytes(t, det, "x.onnx", data)
			if len(findings) != 0 {
				t.Errorf("want no finding for %s, got %d", name, len(findings))
			}
		})
	}
}

func TestONNXIRVersionOnlyConfirms(t *testing.T) {
	// ir_version alone (field 1 varint) confirms an ONNX file.
	data := []byte{0x08, 0x05} // field 1 = 5
	findings := detectBytes(t, NewONNX(), "x.onnx", data)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding for ir_version-only, got %d", len(findings))
	}
	if got := findings[0].Occurrence.Fields["ir_version"]; got != "5" {
		t.Errorf("fields[ir_version] = %q, want 5", got)
	}
	// No producer name -> no architecture claimed.
	if got := findings[0].Claim.Model.Architecture; got != "" {
		t.Errorf("architecture = %q, want empty", got)
	}
}

func TestONNXArchitectureRejectsControlBytes(t *testing.T) {
	if got := onnxArchitecture("py\x01torch"); got != "" {
		t.Errorf("onnxArchitecture with control byte = %q, want empty", got)
	}
	if got := onnxArchitecture("  pytorch  "); got != "pytorch" {
		t.Errorf("onnxArchitecture = %q, want pytorch", got)
	}
}
