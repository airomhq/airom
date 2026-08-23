package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_FileGenerate_Verify_Calendar(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "airom-cli-file-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	pkgDir := filepath.Join(tempDir, "colorado-pkg")

	// 1. Test `airom file generate --state colorado --out <pkgDir>`
	bi := BuildInfo{Version: "1.0.0", Commit: "testcommit", Date: "2026-08-23"}
	root := newRootCmd(bi)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{
		"file", "generate",
		"--state", "colorado",
		"--out", pkgDir,
		"--org", "org_cli_test",
		"--repo", "repo_cli_test",
		"--signer", "Chief Compliance Officer",
		"--email", "compliance@test.com",
	})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("file generate command failed: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, "Generated and Sealed Statutory Filing Package") {
		t.Errorf("expected success output in file generate, got: %s", outStr)
	}

	// Verify manifest exists on disk
	manifestPath := filepath.Join(pkgDir, "filing_manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatalf("expected filing_manifest.json at %s", manifestPath)
	}

	// 2. Test `airom file verify <pkgDir>`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"file", "verify", pkgDir})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("file verify command failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, "Filing Package Verification SUCCESSFUL") {
		t.Errorf("expected verification success, got: %s", outStr)
	}

	// 3. Test `airom file calendar`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"file", "calendar", "--org", "org_cli_test"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("file calendar command failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, "AIROM STATUTORY COMPLIANCE RENEWAL CALENDAR") {
		t.Errorf("expected calendar table banner, got: %s", outStr)
	}

	// 4. Test `airom file calendar --json`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"file", "calendar", "--org", "org_cli_test", "--json"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("file calendar --json command failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, `"organization_id": "org_cli_test"`) {
		t.Errorf("expected json calendar output, got: %s", outStr)
	}

	// 5. Test `airom file submit --pkg <pkgDir>`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"file", "submit", "--pkg", pkgDir})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("file submit command failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, "Statutory Filing Successfully Transmitted & Acknowledged") {
		t.Errorf("expected submit success output, got: %s", outStr)
	}
}
