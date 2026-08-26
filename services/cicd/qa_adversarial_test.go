package cicd

import (
	"testing"
)

func TestQA_AdversarialEmptyFrameworkAndBranch(t *testing.T) {
	compiler := NewCompiler()

	res := compiler.Compile(PipelineSpec{})
	if len(res.Content) == 0 {
		t.Fatalf("expected valid default content on empty spec")
	}
}

func TestQA_AdversarialScriptInjectionInBranchName(t *testing.T) {
	compiler := NewCompiler()

	res := compiler.Compile(PipelineSpec{
		Platform:     PlatformGitHubActions,
		TargetBranch: "main; rm -rf / ;",
	})
	if len(res.Content) == 0 {
		t.Fatalf("expected compiled workflow without panic")
	}
}
