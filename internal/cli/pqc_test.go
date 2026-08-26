package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_PQCSignAndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "model.bin")
	if err := os.WriteFile(testFile, []byte("fake model weights data for pqc test"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	sigFile := filepath.Join(tmpDir, "model.bin.pqc.json")

	// 1. Sign
	rootSign := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var outSign bytes.Buffer
	rootSign.SetOut(&outSign)
	rootSign.SetArgs([]string{"pqc", "sign", "--scheme", "ml-dsa-87", "--out", sigFile, testFile})

	if err := rootSign.Execute(); err != nil {
		t.Fatalf("pqc sign failed: %v", err)
	}

	// 2. Verify
	rootVerify := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var outVerify bytes.Buffer
	rootVerify.SetOut(&outVerify)
	rootVerify.SetArgs([]string{"pqc", "verify", "--sig", sigFile, testFile})

	if err := rootVerify.Execute(); err != nil {
		t.Fatalf("pqc verify failed: %v", err)
	}

	if !bytes.Contains(outVerify.Bytes(), []byte("ML-DSA-87")) {
		t.Errorf("expected ML-DSA-87 in verify output, got:\n%s", outVerify.String())
	}
}
