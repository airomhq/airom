package remediation

import (
	"strings"
	"testing"
)

func TestQA_AdversarialNestedAndDuplicateStrings(t *testing.T) {
	engine := NewEngine()

	// String containing multiple repetitions and substrings
	files := map[string]string{
		"src/complex.py": "m1 = 'gpt-3.5-turbo'\nm2 = 'gpt-3.5-turbo-0613'\nm3 = 'gpt-3.5-turbo'\n",
	}

	plan := engine.CreateRemediationPlan("repo-complex", files)
	if plan == nil || len(plan.Patches) != 1 {
		t.Fatalf("expected 1 patch")
	}

	patch := plan.Patches[0]
	if strings.Contains(patch.ModifiedText, "gpt-3.5-turbo") {
		t.Errorf("expected all gpt-3.5 occurrences to be replaced, got: %s", patch.ModifiedText)
	}
}

func TestQA_AdversarialSpecialCharactersInPath(t *testing.T) {
	engine := NewEngine()

	files := map[string]string{
		"src/path with spaces & unicode/🚀/app.py": "model = 'gpt-3.5-turbo'\n",
	}

	plan := engine.CreateRemediationPlan("repo-unicode", files)
	if plan == nil || len(plan.Patches) != 1 {
		t.Fatalf("expected valid patch on unicode filepath")
	}

	if !strings.Contains(plan.Patches[0].DiffUnified, "🚀") {
		t.Errorf("expected unicode in unified diff output")
	}
}
