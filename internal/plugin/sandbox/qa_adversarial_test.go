package sandbox

import (
	"path/filepath"
	"testing"
)

func TestQA_AdversarialPathTraversalEscapes(t *testing.T) {
	root := filepath.Clean("/workspace/safe-repo")
	policy := DefaultStrictPolicy(root)
	validator := NewPolicyValidator(policy)

	traversalAttacks := []string{
		filepath.Join(root, "../../etc/passwd"),
		filepath.Join(root, "../sibling-secret-repo/key.pem"),
		filepath.Join(root, "subdir/../../../../root/.ssh/id_rsa"),
		filepath.Clean("/etc/shadow"),
		filepath.Clean("C:\\Windows\\System32\\drivers\\etc\\hosts"),
	}

	for _, attack := range traversalAttacks {
		err := validator.ValidateReadAccess(attack)
		if err == nil {
			t.Errorf("security vulnerability: path traversal escape succeeded for %s", attack)
		}
	}
}

func TestQA_AdversarialEmptyPolicyAndRoots(t *testing.T) {
	// Empty policy has no allowed paths -> everything fails closed
	validator := NewPolicyValidator(SecurityPolicy{})

	if err := validator.ValidateReadAccess("/any/path"); err == nil {
		t.Fatalf("expected fail-closed on empty policy")
	}

	if err := validator.ValidateWriteAccess("/any/path"); err == nil {
		t.Fatalf("expected write fail-closed on empty policy")
	}

	if err := validator.ValidateNetworkAccess("google.com"); err == nil {
		t.Fatalf("expected network fail-closed on empty policy")
	}
}
