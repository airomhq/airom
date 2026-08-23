package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_WorkforceAssess_And_Notice(t *testing.T) {
	bi := BuildInfo{Version: "1.0.0", Commit: "workforcecommit", Date: "2026-08-23"}

	// 1. Test `airom workforce assess`
	root := newRootCmd(bi)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"workforce", "assess", "--org", "org_cli_workforce", "--system", "Enterprise-AI"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("workforce assess command failed: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, "AI WORKFORCE IMPACT & JOB DISPLACEMENT RISK DASHBOARD") {
		t.Errorf("expected dashboard header, got: %s", outStr)
	}
	if !strings.Contains(outStr, "DEPARTMENT DISPLACEMENT RISK HEATMAP") {
		t.Errorf("expected department heatmap, got: %s", outStr)
	}

	// 2. Test `airom workforce assess --json`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"workforce", "assess", "--org", "org_cli_workforce", "--json"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("workforce assess --json failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, `"organization_id": "org_cli_workforce"`) {
		t.Errorf("expected json output, got: %s", outStr)
	}

	// 3. Test `airom workforce notice --role "Software Engineer"`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"workforce", "notice", "--role", "Software Engineer"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("workforce notice failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, "STATUTORY DUTY-OF-CARE EMPLOYEE NOTIFICATION") {
		t.Errorf("expected statutory notice header, got: %s", outStr)
	}
	if !strings.Contains(outStr, "Software Engineer") {
		t.Errorf("expected role name in notice, got: %s", outStr)
	}

	// 4. Test `airom workforce notice --role "Talent Recruiter" --out <file>`
	tempDir, err := os.MkdirTemp("", "airom-workforce-notice-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	noticePath := filepath.Join(tempDir, "duty_of_care_notice.md")
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"workforce", "notice", "--role", "Talent Recruiter", "--out", noticePath})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("workforce notice --out failed: %v", err)
	}

	if _, err := os.Stat(noticePath); os.IsNotExist(err) {
		t.Fatalf("expected notice file at %s", noticePath)
	}
}
