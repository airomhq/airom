package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRegWatchCmd_Feed(t *testing.T) {
	cmd := newRegWatchCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"feed"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected feed command to succeed, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CO-AG") || !strings.Contains(out, "CA-CPPA") || !strings.Contains(out, "EU-AI-OFFICE") {
		t.Errorf("feed output missing expected jurisdictions:\n%s", out)
	}
}

func TestRegWatchCmd_CheckAll(t *testing.T) {
	cmd := newRegWatchCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"check"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected check command to succeed, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "SYNCHRONIZED") {
		t.Errorf("expected synchronized status in output:\n%s", out)
	}
}

func TestRegWatchCmd_CheckSingleJSON(t *testing.T) {
	cmd := newRegWatchCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"check", "CO-AG", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected check single command to succeed, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"jurisdiction": "CO-AG"`) {
		t.Errorf("expected JSON output containing jurisdiction CO-AG, got:\n%s", out)
	}
}

func TestRegWatchCmd_Diff(t *testing.T) {
	cmd := newRegWatchCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"diff", "CO-AG"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected diff command to succeed, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "AIROM RegWatch Statutory Diff: CO-AG") {
		t.Errorf("expected header in diff output, got:\n%s", out)
	}
}
