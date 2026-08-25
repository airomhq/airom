package tenant

import (
	"testing"
)

func TestTenant_QuotaEnforcement(t *testing.T) {
	manager := NewManager()

	org, err := manager.CreateOrganization("org-comm", "Community Team", TierCommunity)
	if err != nil || org == nil {
		t.Fatalf("failed to create organization: %v", err)
	}

	// Community allows 5 repos
	for i := 0; i < 5; i++ {
		err := manager.RegisterRepository("org-comm", string(rune('a'+i)))
		if err != nil {
			t.Fatalf("failed to register repo within quota: %v", err)
		}
	}

	// 6th repo must be rejected
	err = manager.RegisterRepository("org-comm", "repo-overflow")
	if err == nil {
		t.Fatalf("expected quota error on 6th repository")
	}
}

func TestTenant_CrossTenantIsolation(t *testing.T) {
	manager := NewManager()

	_, _ = manager.CreateOrganization("org-a", "Org A", TierEnterprise)
	_, _ = manager.CreateOrganization("org-b", "Org B", TierEnterprise)

	_ = manager.RegisterRepository("org-a", "repo-shared-1")

	// Org B attempts to claim Org A's repository
	err := manager.RegisterRepository("org-b", "repo-shared-1")
	if err == nil {
		t.Fatalf("SECURITY VIOLATION: Org B successfully claimed Org A's repository")
	}
}
