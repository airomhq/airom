package cli

import (
	"bytes"
	"testing"
)

func TestCLI_ComplianceCommandHelp(t *testing.T) {
	root := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"compliance", "--help"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error executing compliance --help: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("colorado-ai-act")) {
		t.Errorf("expected compliance help to mention colorado-ai-act, got:\n%s", out.String())
	}
}
