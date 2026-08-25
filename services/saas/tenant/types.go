// Package tenant implements multi-tenant cryptographic partitioning and organization quota management.
package tenant

import (
	"time"
)

// Tier defines the commercial subscription tier of an organization.
type Tier string

const (
	TierCommunity  Tier = "COMMUNITY"
	TierPro        Tier = "PRO"
	TierEnterprise Tier = "ENTERPRISE"
	TierSovereign  Tier = "SOVEREIGN"
)

// QuotaLimits defines the resource ceilings allocated to an organization tier.
type QuotaLimits struct {
	MaxRepositories     int      `json:"maxRepositories"`
	MaxMonthlyScans     int      `json:"maxMonthlyScans"`
	MaxConcurrentAgents int      `json:"maxConcurrentAgents"`
	MaxCustomRules      int      `json:"maxCustomRules"`
	AllowedFeatures     []string `json:"allowedFeatures"`
}

// Organization models an isolated enterprise tenant in the SaaS control plane.
type Organization struct {
	ID           string      `json:"id"`   // e.g. "org-yc-demo"
	Name         string      `json:"name"` // e.g. "Acme Corp"
	Tier         Tier        `json:"tier"`
	Quota        QuotaLimits `json:"quota"`
	ActiveRepos  int         `json:"activeRepos"`
	MonthlyScans int         `json:"monthlyScans"`
	CreatedAt    time.Time   `json:"createdAt"`
	UpdatedAt    time.Time   `json:"updatedAt"`
}
