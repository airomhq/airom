package cli

import (
	"bytes"
	"testing"
)

func TestCLI_CockpitCommandHelp(t *testing.T) {
	root := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"cockpit", "--help"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error executing cockpit --help: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("cockpit")) {
		t.Errorf("expected cockpit help, got:\n%s", out.String())
	}
}

func TestCLI_CockpitNonBlockingRun(t *testing.T) {
	root := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"cockpit", "--port", "8099", "--no-block"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error executing cockpit non-blocking: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("8099")) {
		t.Errorf("expected port in cockpit output, got:\n%s", out.String())
	}
}
