package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_CICDGenerate(t *testing.T) {
	tmpDir := t.TempDir()
	outWorkflow := filepath.Join(tmpDir, "airom-test-ci.yml")

	root := newRootCmd(BuildInfo{Version: "v0.4.5"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"cicd", "--platform", "github", "--framework", "eu-ai-act", "--out", outWorkflow})

	if err := root.Execute(); err != nil {
		t.Fatalf("cicd command failed: %v", err)
	}

	data, err := os.ReadFile(outWorkflow)
	if err != nil {
		t.Fatalf("failed to read generated workflow: %v", err)
	}

	if !bytes.Contains(data, []byte("eu-ai-act")) {
		t.Errorf("expected eu-ai-act in workflow, got:\n%s", string(data))
	}
}
