package sandbox

import (
	"path/filepath"
	"testing"
)

func TestSandbox_PathValidation(t *testing.T) {
	root := filepath.Clean("/workspace/project")
	policy := DefaultStrictPolicy(root)
	validator := NewPolicyValidator(policy)

	// Permitted subpaths
	if err := validator.ValidateReadAccess(filepath.Join(root, "src/main.py")); err != nil {
		t.Errorf("expected read access permitted, got %v", err)
	}

	// Forbidden parent path
	if err := validator.ValidateReadAccess("/etc/shadow"); err == nil {
		t.Errorf("expected forbidden access for /etc/shadow")
	}

	// Forbidden write path
	if err := validator.ValidateWriteAccess(filepath.Join(root, "src/main.py")); err == nil {
		t.Errorf("expected write forbidden under strict policy")
	}
}

func TestSandbox_NetworkPolicy(t *testing.T) {
	policy := DefaultStrictPolicy("/workspace")
	validator := NewPolicyValidator(policy)

	if err := validator.ValidateNetworkAccess("api.openai.com"); err == nil {
		t.Errorf("expected network access blocked under strict policy")
	}

	// Permissive policy
	permissive := SecurityPolicy{AllowNetworkOutbound: true}
	pValidator := NewPolicyValidator(permissive)
	if err := pValidator.ValidateNetworkAccess("api.openai.com"); err != nil {
		t.Errorf("expected network allowed, got %v", err)
	}
}

func TestSandbox_LandlockRuleGeneration(t *testing.T) {
	policy := SecurityPolicy{
		AllowedReadPaths:  []string{"/workspace/code"},
		AllowedWritePaths: []string{"/workspace/code/build"},
	}
	validator := NewPolicyValidator(policy)

	rules := validator.GenerateLandlockRules()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}
