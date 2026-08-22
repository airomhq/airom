package auth

import (
	"time"
)

// Role defines the enterprise RBAC role level.
type Role string

const (
	RoleAdmin             Role = "ADMIN"
	RoleComplianceOfficer Role = "COMPLIANCE_OFFICER"
	RoleDeveloper         Role = "DEVELOPER"
	RoleAuditor           Role = "AUDITOR"
)

// Permission defines a granular action capability.
type Permission string

const (
	PermOrgManage       Permission = "org:manage"
	PermUserManage      Permission = "user:manage"
	PermKeyRotate       Permission = "key:rotate"
	PermScanWrite       Permission = "scan:write"
	PermReportGenerate  Permission = "report:generate"
	PermDocumentCertify Permission = "document:certify"
	PermAuditRead       Permission = "audit:read"
	PermLedgerVerify    Permission = "ledger:verify"
)

// User represents an authenticated enterprise identity.
type User struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	Role        Role       `json:"role"`
	SSOProvider string     `json:"sso_provider,omitempty"` // Okta, AzureAD, GoogleWorkspace
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	IsActive    bool       `json:"is_active"`
}

// APIKey represents a machine-to-machine scoped access token.
type APIKey struct {
	ID          string       `json:"id"`
	OrgID       string       `json:"org_id"`
	KeyPrefix   string       `json:"key_prefix"` // e.g. "airom_live_a1b2..."
	KeyHash     string       `json:"-"`          // SHA-256 hash of raw key
	Name        string       `json:"name"`
	Role        Role         `json:"role"`
	Permissions []Permission `json:"permissions"`
	CreatedAt   time.Time    `json:"created_at"`
	ExpiresAt   *time.Time   `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time   `json:"last_used_at,omitempty"`
	IsActive    bool         `json:"is_active"`
}

// SSOConfig defines organization-level identity federation settings.
type SSOConfig struct {
	OrgID           string    `json:"org_id"`
	ProviderType    string    `json:"provider_type"` // SAML2, OIDC
	EntityID        string    `json:"entity_id"`
	SSOURL          string    `json:"sso_url"`
	CertPublicKey   string    `json:"cert_public_key,omitempty"`
	DomainWhitelist []string  `json:"domain_whitelist"`
	IsActive        bool      `json:"is_active"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// AuthClaims represents parsed session token claims.
type AuthClaims struct {
	UserID      string       `json:"user_id"`
	OrgID       string       `json:"org_id"`
	Email       string       `json:"email"`
	Role        Role         `json:"role"`
	Permissions []Permission `json:"permissions"`
	TokenType   string       `json:"token_type"` // "user_session" or "api_key"
	IssuedAt    time.Time    `json:"issued_at"`
	ExpiresAt   time.Time    `json:"expires_at"`
}

// AuthEvent records an audit log entry for authentication and authorization.
type AuthEvent struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	UserID    string    `json:"user_id"`
	EventType string    `json:"event_type"` // LOGIN_SUCCESS, SSO_LOGIN, UNAUTHORIZED_ACCESS, KEY_MINTED, ROLE_CHANGED
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}
