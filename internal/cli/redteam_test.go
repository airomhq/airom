package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLI_RedTeam(t *testing.T) {
	bi := BuildInfo{Version: "1.0.0", Commit: "redcommit", Date: "2026-08-23"}

	// 1. Test `airom redteam probe`
	root := newRootCmd(bi)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"redteam", "probe", "--target", "https://api.gateway.internal", "--model", "gpt-4o"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("redteam probe failed: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, "AIROM AUTOMATED RED TEAM PENETRATION & ADVERSARIAL AUDIT REPORT") {
		t.Errorf("expected audit header, got: %s", outStr)
	}
	if !strings.Contains(outStr, "Direct Instruction Override") {
		t.Errorf("expected probe name in output, got: %s", outStr)
	}

	// 2. Test `airom redteam probe --json`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"redteam", "probe", "--json"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("redteam probe --json failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, `"assessment_id":`) {
		t.Errorf("expected assessment JSON output, got: %s", outStr)
	}
}
