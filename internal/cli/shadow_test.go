package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_ShadowScan(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "airom-shadow-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create test shadow AI file
	envPath := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envPath, []byte("OPENAI_API_KEY=sk-proj-019283746501928374650192837465\n"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	bi := BuildInfo{Version: "1.0.0", Commit: "shadowcommit", Date: "2026-08-23"}

	// 1. Test `airom shadow scan <tempDir>`
	root := newRootCmd(bi)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"shadow", "scan", tempDir, "--org", "org_cli_shadow"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("shadow scan failed: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, "AIROM SHADOW AI & SAAS CONNECTOR ASSET INVENTORY") {
		t.Errorf("expected header banner, got: %s", outStr)
	}
	if !strings.Contains(outStr, "OPENAI") {
		t.Errorf("expected OPENAI finding, got: %s", outStr)
	}

	// 2. Test `airom shadow scan <tempDir> --json`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"shadow", "scan", tempDir, "--org", "org_cli_shadow", "--json"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("shadow scan --json failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, `"organization_id": "org_cli_shadow"`) {
		t.Errorf("expected json output, got: %s", outStr)
	}
}
