package cli

import (
	"bytes"
	"testing"
)

func TestCLI_ReportCommandHelp(t *testing.T) {
	root := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"report", "--help"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error executing report --help: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("PDF")) {
		t.Errorf("expected report help to mention PDF, got:\n%s", out.String())
	}
}
