package billing

import (
	"fmt"
	"sync"
	"time"
)

// Service manages subscriptions, customer accounts, and quota enforcement.
type Service struct {
	mu            sync.RWMutex
	webhookSecret string
	accounts      map[string]*CustomerAccount // orgID -> CustomerAccount
	usage         map[string]*UsageMetrics    // orgID:YYYY-MM -> UsageMetrics
}

// NewService creates a new Billing & Entitlements service.
func NewService(webhookSecret string) *Service {
	return &Service{
		webhookSecret: webhookSecret,
		accounts:      make(map[string]*CustomerAccount),
		usage:         make(map[string]*UsageMetrics),
	}
}

func currentMonthKey(orgID string) string {
	return fmt.Sprintf("%s:%s", orgID, time.Now().UTC().Format("2006-01"))
}

// GetAccount retrieves billing profile for an organization.
func (s *Service) GetAccount(orgID string) (*CustomerAccount, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	acc, ok := s.accounts[orgID]
	if !ok {
		return nil, false
	}
	cp := *acc
	return &cp, true
}

// ProvisionAccount creates or updates an organization billing profile.
func (s *Service) ProvisionAccount(acc CustomerAccount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts[acc.OrgID] = &acc
}

// GetUsage retrieves current month usage metrics.
func (s *Service) GetUsage(orgID string) UsageMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := currentMonthKey(orgID)
	u, ok := s.usage[key]
	if !ok {
		return UsageMetrics{
			OrgID:        orgID,
			CurrentMonth: time.Now().UTC().Format("2006-01"),
		}
	}
	return *u
}

// CheckScanAllowed validates whether organization is allowed to execute a scan.
func (s *Service) CheckScanAllowed(orgID string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	acc, ok := s.accounts[orgID]
	tier := TierCommunity
	status := StatusActive

	if ok {
		tier = acc.Tier
		status = acc.Status
	}

	if status != StatusActive && status != StatusTrialing {
		return ErrSubscriptionInactive
	}

	quotas := DefaultQuotas(tier)
	if quotas.MaxScansPerMonth == -1 {
		return nil // Unlimited
	}

	key := currentMonthKey(orgID)
	u, ok := s.usage[key]
	if ok && u.ScansCount >= quotas.MaxScansPerMonth {
		return fmt.Errorf("%w: used %d of %d scans", ErrQuotaExceeded, u.ScansCount, quotas.MaxScansPerMonth)
	}

	return nil
}

// RecordScanUsage increments scan counter for current billing month.
func (s *Service) RecordScanUsage(orgID string) error {
	if err := s.CheckScanAllowed(orgID); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := currentMonthKey(orgID)
	u, ok := s.usage[key]
	if !ok {
		u = &UsageMetrics{
			OrgID:        orgID,
			CurrentMonth: time.Now().UTC().Format("2006-01"),
		}
		s.usage[key] = u
	}
	u.ScansCount++
	u.LastScanTimestamp = time.Now().UTC()
	return nil
}

// CheckFeatureAllowed verifies if a premium feature is accessible in current tier.
func (s *Service) CheckFeatureAllowed(orgID string, feature string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	acc, ok := s.accounts[orgID]
	tier := TierCommunity
	if ok {
		tier = acc.Tier
	}

	quotas := DefaultQuotas(tier)
	switch feature {
	case "siem_streaming":
		if !quotas.SIEMStreamingAllowed {
			return fmt.Errorf("%w: SIEM event streaming requires Enterprise or Strategic tier", ErrFeatureNotAllowed)
		}
	case "custom_sso":
		if !quotas.CustomSSOAllowed {
			return fmt.Errorf("%w: SAML / Okta SSO requires Enterprise tier", ErrFeatureNotAllowed)
		}
	case "private_packs":
		if !quotas.PrivatePacksAllowed {
			return fmt.Errorf("%w: custom internal regulatory packs require Enterprise tier", ErrFeatureNotAllowed)
		}
	}
	return nil
}
