package cicd

import (
	"strings"
	"testing"
)

func TestCICD_CompileGitHubActions(t *testing.T) {
	compiler := NewCompiler()

	res := compiler.Compile(PipelineSpec{
		Platform:     PlatformGitHubActions,
		Framework:    "eu-ai-act",
		FailOnGaps:   true,
		GeneratePDF:  true,
		TargetBranch: "main",
	})

	if res.FilePath != ".github/workflows/airom-governance.yml" {
		t.Errorf("unexpected file path: %s", res.FilePath)
	}

	if !strings.Contains(res.Content, "eu-ai-act") || !strings.Contains(res.Content, "--fail-on compliance:gap") {
		t.Errorf("expected eu-ai-act and gap flags, got:\n%s", res.Content)
	}
}

func TestCICD_CompilePreCommitHook(t *testing.T) {
	compiler := NewCompiler()

	res := compiler.Compile(PipelineSpec{
		Platform:  PlatformPreCommit,
		Framework: "colorado-ai-act",
	})

	if res.FilePath != ".git/hooks/pre-commit" {
		t.Errorf("unexpected hook path: %s", res.FilePath)
	}

	if !strings.Contains(res.Content, "#!/bin/sh") {
		t.Errorf("expected shell script header, got:\n%s", res.Content)
	}
}
