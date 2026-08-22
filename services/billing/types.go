package billing

import (
	"errors"
	"time"
)

var (
	ErrQuotaExceeded        = errors.New("monthly tier quota exceeded")
	ErrFeatureNotAllowed    = errors.New("feature not included in current subscription tier")
	ErrSubscriptionInactive = errors.New("subscription is inactive or past due")
	ErrCustomerNotFound     = errors.New("billing customer not found")
)

// PricingTier defines subscription levels.
type PricingTier string

const (
	TierCommunity  PricingTier = "community"  // $0
	TierTeam       PricingTier = "team"       // $499/mo
	TierEnterprise PricingTier = "enterprise" // $24,000 - $60,000 / yr
	TierStrategic  PricingTier = "strategic"  // $100,000+ / yr
)

// SubscriptionStatus represents Stripe subscription lifecycle state.
type SubscriptionStatus string

const (
	StatusActive     SubscriptionStatus = "active"
	StatusTrialing   SubscriptionStatus = "trialing"
	StatusPastDue    SubscriptionStatus = "past_due"
	StatusCanceled   SubscriptionStatus = "canceled"
	StatusUnpaid     SubscriptionStatus = "unpaid"
	StatusIncomplete SubscriptionStatus = "incomplete"
)

// TierQuotas holds limits and feature gates for each tier.
type TierQuotas struct {
	MaxScansPerMonth     int  `json:"max_scans_per_month"` // -1 for unlimited
	MaxRepos             int  `json:"max_repos"`
	MaxSeats             int  `json:"max_seats"`
	RetentionDays        int  `json:"retention_days"`
	PrivatePacksAllowed  bool `json:"private_packs_allowed"`
	SIEMStreamingAllowed bool `json:"siem_streaming_allowed"`
	CustomSSOAllowed     bool `json:"custom_sso_allowed"`
	DedicatedSupportSLA  int  `json:"dedicated_support_sla_hours"` // in hours, 0 = community
}

// DefaultQuotas returns statutory tier limitations per Institutional Pricing Specs.
func DefaultQuotas(tier PricingTier) TierQuotas {
	switch tier {
	case TierTeam:
		return TierQuotas{
			MaxScansPerMonth:     500,
			MaxRepos:             25,
			MaxSeats:             10,
			RetentionDays:        90,
			PrivatePacksAllowed:  false,
			SIEMStreamingAllowed: false,
			CustomSSOAllowed:     false,
			DedicatedSupportSLA:  24,
		}
	case TierEnterprise:
		return TierQuotas{
			MaxScansPerMonth:     10000,
			MaxRepos:             500,
			MaxSeats:             100,
			RetentionDays:        365 * 3, // 3-year statutory audit retention
			PrivatePacksAllowed:  true,
			SIEMStreamingAllowed: true,
			CustomSSOAllowed:     true,
			DedicatedSupportSLA:  4,
		}
	case TierStrategic:
		return TierQuotas{
			MaxScansPerMonth:     -1, // Unlimited
			MaxRepos:             -1,
			MaxSeats:             -1,
			RetentionDays:        365 * 7, // 7-year institutional compliance retention
			PrivatePacksAllowed:  true,
			SIEMStreamingAllowed: true,
			CustomSSOAllowed:     true,
			DedicatedSupportSLA:  1,
		}
	default: // Community
		return TierQuotas{
			MaxScansPerMonth:     50,
			MaxRepos:             3,
			MaxSeats:             2,
			RetentionDays:        14,
			PrivatePacksAllowed:  false,
			SIEMStreamingAllowed: false,
			CustomSSOAllowed:     false,
			DedicatedSupportSLA:  0,
		}
	}
}

// CustomerAccount represents an enterprise billing profile.
type CustomerAccount struct {
	OrgID                string             `json:"org_id"`
	StripeCustomerID     string             `json:"stripe_customer_id"`
	StripeSubscriptionID string             `json:"stripe_subscription_id,omitempty"`
	Tier                 PricingTier        `json:"tier"`
	Status               SubscriptionStatus `json:"status"`
	CurrentPeriodStart   time.Time          `json:"current_period_start"`
	CurrentPeriodEnd     time.Time          `json:"current_period_end"`
	CancelAtPeriodEnd    bool               `json:"cancel_at_period_end"`
	BillingEmail         string             `json:"billing_email"`
}

// UsageMetrics tracks current consumption against monthly tier quotas.
type UsageMetrics struct {
	OrgID             string    `json:"org_id"`
	CurrentMonth      string    `json:"current_month"` // "2026-08"
	ScansCount        int       `json:"scans_count"`
	ReportsCount      int       `json:"reports_count"`
	ActiveReposCount  int       `json:"active_repos_count"`
	ActiveUsersCount  int       `json:"active_users_count"`
	LastScanTimestamp time.Time `json:"last_scan_timestamp"`
}

// StripeWebhookEvent represents a decoded Stripe webhook envelope.
type StripeWebhookEvent struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Created  int64           `json:"created"`
	Data     StripeEventData `json:"data"`
	Livemode bool            `json:"livemode"`
}

type StripeEventData struct {
	Object map[string]interface{} `json:"object"`
}
