package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_TranspileCommand(t *testing.T) {
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "bom.cdx.json")
	dstFile := filepath.Join(tmpDir, "bom.spdx3.json")

	cdxData := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"model"}]}`)
	if err := os.WriteFile(srcFile, cdxData, 0o644); err != nil {
		t.Fatalf("failed to write cdx file: %v", err)
	}

	root := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"transpile", "--from", "cyclonedx", "--to", "spdx3", "--out", dstFile, srcFile})

	if err := root.Execute(); err != nil {
		t.Fatalf("transpile command failed: %v", err)
	}

	outData, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("failed to read transpiled file: %v", err)
	}

	if !bytes.Contains(outData, []byte("AIROM-Transpiler-v2")) {
		t.Errorf("expected transpiler marker, got:\n%s", string(outData))
	}
}
