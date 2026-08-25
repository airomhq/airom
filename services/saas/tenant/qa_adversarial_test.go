package tenant

import (
	"testing"
)

func TestQA_AdversarialUnknownOrgOperations(t *testing.T) {
	manager := NewManager()

	err := manager.RecordScan("org-ghost")
	if err == nil {
		t.Fatalf("expected error recording scan for non-existent org")
	}

	err = manager.RegisterRepository("org-ghost", "repo-1")
	if err == nil {
		t.Fatalf("expected error registering repo for non-existent org")
	}
}

func TestQA_AdversarialDuplicateOrgRegistration(t *testing.T) {
	manager := NewManager()

	_, err := manager.CreateOrganization("org-dup", "Dup Org", TierPro)
	if err != nil {
		t.Fatalf("first registration should succeed: %v", err)
	}

	_, err = manager.CreateOrganization("org-dup", "Dup Org 2", TierEnterprise)
	if err == nil {
		t.Fatalf("expected duplicate org registration to fail")
	}
}
