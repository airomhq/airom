package tenant

import (
	"fmt"
	"sync"
	"time"
)

// Manager coordinates multi-tenant organization creation, quota limits, and security boundaries.
type Manager struct {
	mu    sync.RWMutex
	orgs  map[string]*Organization
	repos map[string]string // Key: repoID -> Value: orgID
}

// NewManager constructs a new SaaS tenant manager.
func NewManager() *Manager {
	return &Manager{
		orgs:  make(map[string]*Organization),
		repos: make(map[string]string),
	}
}

// DefaultTierQuotas returns canonical quotas for a subscription tier.
func DefaultTierQuotas(tier Tier) QuotaLimits {
	switch tier {
	case TierSovereign:
		return QuotaLimits{
			MaxRepositories:     10000,
			MaxMonthlyScans:     1000000,
			MaxConcurrentAgents: 500,
			MaxCustomRules:      5000,
			AllowedFeatures:     []string{"ALL", "AIR_GAP", "NEURAL_FORENSICS", "SOVEREIGN_POA", "EXPORT_CONTROL"},
		}
	case TierEnterprise:
		return QuotaLimits{
			MaxRepositories:     1000,
			MaxMonthlyScans:     100000,
			MaxConcurrentAgents: 100,
			MaxCustomRules:      1000,
			AllowedFeatures:     []string{"ALL", "CLOUD_CONNECTORS", "ITSM_BIDIRECTIONAL", "SIEM_STREAMING"},
		}
	case TierPro:
		return QuotaLimits{
			MaxRepositories:     50,
			MaxMonthlyScans:     5000,
			MaxConcurrentAgents: 10,
			MaxCustomRules:      50,
			AllowedFeatures:     []string{"STATE_FILINGS", "BASIC_REPORTING", "API_ACCESS"},
		}
	default: // Community
		return QuotaLimits{
			MaxRepositories:     5,
			MaxMonthlyScans:     100,
			MaxConcurrentAgents: 1,
			MaxCustomRules:      5,
			AllowedFeatures:     []string{"BASIC_SCAN"},
		}
	}
}

// CreateOrganization registers a new tenant organization.
func (m *Manager) CreateOrganization(id, name string, tier Tier) (*Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.orgs[id]; exists {
		return nil, fmt.Errorf("organization %s already exists", id)
	}

	now := time.Now().UTC()
	org := &Organization{
		ID:        id,
		Name:      name,
		Tier:      tier,
		Quota:     DefaultTierQuotas(tier),
		CreatedAt: now,
		UpdatedAt: now,
	}

	m.orgs[id] = org
	return org, nil
}

// RegisterRepository registers a repository under an organization, checking quota ceilings.
func (m *Manager) RegisterRepository(orgID, repoID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	org, exists := m.orgs[orgID]
	if !exists {
		return fmt.Errorf("organization %s not found", orgID)
	}

	if existingOrg, bound := m.repos[repoID]; bound {
		if existingOrg != orgID {
			return fmt.Errorf("security violation: repository %s belongs to organization %s", repoID, existingOrg)
		}
		return nil
	}

	if org.ActiveRepos >= org.Quota.MaxRepositories {
		return fmt.Errorf("quota exceeded: organization %s has reached repository limit of %d", orgID, org.Quota.MaxRepositories)
	}

	org.ActiveRepos++
	m.repos[repoID] = orgID
	return nil
}

// RecordScan checks monthly scan limits and increments scan counter.
func (m *Manager) RecordScan(orgID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	org, exists := m.orgs[orgID]
	if !exists {
		return fmt.Errorf("organization %s not found", orgID)
	}

	if org.MonthlyScans >= org.Quota.MaxMonthlyScans {
		return fmt.Errorf("scan quota exceeded: limit of %d scans reached for this billing cycle", org.Quota.MaxMonthlyScans)
	}

	org.MonthlyScans++
	return nil
}

// GetOrganization returns tenant profile.
func (m *Manager) GetOrganization(orgID string) (*Organization, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	org, exists := m.orgs[orgID]
	return org, exists
}
