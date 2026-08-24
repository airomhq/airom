package bundle

import (
	"errors"
	"testing"
)

func TestAirGap_BuildAndVerifyCleanBundle(t *testing.T) {
	compiler := NewCompiler([]byte("test-scif-secret-key-12345"))

	payloads := map[string][]byte{
		"rules/eu_ai_act.yaml":           []byte("name: eu-ai-act-pack\nversion: 1.0"),
		"parsers/treesitter_python.wasm": []byte("\x00asm\x01\x00\x00\x00_wasm_binary_data"),
		"vulndb/osv_models.json":         []byte(`{"cve": "CVE-2026-1001"}`),
	}

	pkg := compiler.BuildBundle("bundle-scif-001", "v1.0.0", payloads, 10, 5, 2500)
	if !pkg.Manifest.AirGapCertified {
		t.Errorf("expected certified manifest")
	}

	err := compiler.VerifyBundle(pkg)
	if err != nil {
		t.Fatalf("expected valid bundle verification, got %v", err)
	}
}

func TestAirGap_TamperedPayloadDetection(t *testing.T) {
	compiler := NewCompiler([]byte("test-scif-secret-key-12345"))

	payloads := map[string][]byte{
		"rules/rule.yaml": []byte("original rule content"),
	}

	pkg := compiler.BuildBundle("bundle-tamper", "v1.0.0", payloads, 1, 1, 10)

	// Tamper payload byte
	pkg.Payloads["rules/rule.yaml"] = []byte("tampered rule content")

	err := compiler.VerifyBundle(pkg)
	if err == nil || !errors.Is(err, ErrCorruptedArchive) {
		t.Fatalf("expected ErrCorruptedArchive upon payload tampering")
	}
}

func TestAirGap_ForgedSignatureDetection(t *testing.T) {
	compiler := NewCompiler([]byte("test-scif-secret-key-12345"))

	payloads := map[string][]byte{"data.bin": []byte("sample")}
	pkg := compiler.BuildBundle("bundle-forge", "v1.0.0", payloads, 1, 1, 1)

	// Forge signature
	pkg.Manifest.CosignSignature = "0000000000000000000000000000000000000000000000000000000000000000"

	err := compiler.VerifyBundle(pkg)
	if err == nil || !errors.Is(err, ErrCorruptedArchive) {
		t.Fatalf("expected ErrCorruptedArchive on forged signature")
	}
}
