package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLI_Dashboard(t *testing.T) {
	bi := BuildInfo{Version: "1.0.0", Commit: "dashcommit", Date: "2026-08-23"}

	// 1. Test `airom dashboard`
	root := newRootCmd(bi)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"dashboard"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("dashboard command failed: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, "AIROM ENTERPRISE COMPLIANCE & AI GOVERNANCE EXECUTIVE DASHBOARD") {
		t.Errorf("expected dashboard header, got: %s", outStr)
	}
	if !strings.Contains(outStr, "Core Payments") {
		t.Errorf("expected subsidiary row, got: %s", outStr)
	}

	// 2. Test `airom dashboard --json`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"dashboard", "--json"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("dashboard --json failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, `"matrix_id":`) {
		t.Errorf("expected matrix JSON output, got: %s", outStr)
	}
}
