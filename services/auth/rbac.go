package auth

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrUnauthorized     = errors.New("unauthorized: missing valid authentication credentials")
	ErrForbidden        = errors.New("forbidden: insufficient role permissions")
	ErrOrgMismatch      = errors.New("forbidden: cross-organization access denied")
	ErrInvalidRole      = errors.New("invalid role assignment")
)

// rolePermissions defines the strict RBAC permission matrix.
var rolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermOrgManage,
		PermUserManage,
		PermKeyRotate,
		PermScanWrite,
		PermReportGenerate,
		PermDocumentCertify,
		PermAuditRead,
		PermLedgerVerify,
	},
	RoleComplianceOfficer: {
		PermDocumentCertify,
		PermReportGenerate,
		PermAuditRead,
		PermLedgerVerify,
	},
	RoleDeveloper: {
		PermScanWrite,
		PermReportGenerate,
		PermLedgerVerify,
	},
	RoleAuditor: {
		PermAuditRead,
		PermLedgerVerify,
	},
}

// GetRolePermissions returns all permissions granted to a role.
func GetRolePermissions(role Role) []Permission {
	perms, exists := rolePermissions[role]
	if !exists {
		return nil
	}
	return append([]Permission{}, perms...)
}

// HasPermission reports whether a given role holds the required permission.
func HasPermission(role Role, required Permission) bool {
	perms := rolePermissions[role]
	for _, p := range perms {
		if p == required {
			return true
		}
	}
	return false
}

// ValidateRole ensures a role string is valid.
func ValidateRole(role Role) error {
	switch role {
	case RoleAdmin, RoleComplianceOfficer, RoleDeveloper, RoleAuditor:
		return nil
	default:
		return fmt.Errorf("%w: %q (must be ADMIN, COMPLIANCE_OFFICER, DEVELOPER, or AUDITOR)", ErrInvalidRole, role)
	}
}

// Authorize validates that claims contain the required permission.
func Authorize(claims *AuthClaims, requiredPerm Permission) error {
	if claims == nil {
		return ErrUnauthorized
	}

	// 1. Check direct permissions slice on claims
	for _, p := range claims.Permissions {
		if p == requiredPerm {
			return nil
		}
	}

	// 2. Check role-level permission mapping
	if HasPermission(claims.Role, requiredPerm) {
		return nil
	}

	return fmt.Errorf("%w: role %q lacks permission %q", ErrForbidden, claims.Role, requiredPerm)
}

// AuthorizeOrg ensures the caller belongs to the target organization.
func AuthorizeOrg(claims *AuthClaims, targetOrgID string) error {
	if claims == nil {
		return ErrUnauthorized
	}
	if strings.TrimSpace(targetOrgID) == "" {
		return nil
	}
	if claims.OrgID != targetOrgID {
		return fmt.Errorf("%w: token org=%q, target org=%q", ErrOrgMismatch, claims.OrgID, targetOrgID)
	}
	return nil
}
