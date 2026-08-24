package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
)

// PolicyValidator validates and enforces filesystem and network access policies.
type PolicyValidator struct {
	policy SecurityPolicy
}

// NewPolicyValidator constructs a validator with a security policy.
func NewPolicyValidator(policy SecurityPolicy) *PolicyValidator {
	return &PolicyValidator{policy: policy}
}

// ValidateReadAccess checks if a target path is permitted for read by the policy.
func (v *PolicyValidator) ValidateReadAccess(targetPath string) error {
	cleanTarget := filepath.Clean(targetPath)

	for _, allowed := range v.policy.AllowedReadPaths {
		cleanAllowed := filepath.Clean(allowed)
		if cleanTarget == cleanAllowed || strings.HasPrefix(cleanTarget, cleanAllowed+string(filepath.Separator)) {
			return nil
		}
	}

	return fmt.Errorf("%w: read access forbidden for %s", ErrAccessDenied, targetPath)
}

// ValidateWriteAccess checks if a target path is permitted for write by the policy.
func (v *PolicyValidator) ValidateWriteAccess(targetPath string) error {
	if len(v.policy.AllowedWritePaths) == 0 {
		return fmt.Errorf("%w: plugin has zero write permissions", ErrAccessDenied)
	}

	cleanTarget := filepath.Clean(targetPath)
	for _, allowed := range v.policy.AllowedWritePaths {
		cleanAllowed := filepath.Clean(allowed)
		if cleanTarget == cleanAllowed || strings.HasPrefix(cleanTarget, cleanAllowed+string(filepath.Separator)) {
			return nil
		}
	}

	return fmt.Errorf("%w: write access forbidden for %s", ErrAccessDenied, targetPath)
}

// ValidateNetworkAccess checks if network outbound is permitted.
func (v *PolicyValidator) ValidateNetworkAccess(destHost string) error {
	if !v.policy.AllowNetworkOutbound {
		return fmt.Errorf("%w: outbound network disabled (blocked connect to %s)", ErrAccessDenied, destHost)
	}
	return nil
}

// GenerateLandlockRules generates Linux Landlock rule descriptors.
func (v *PolicyValidator) GenerateLandlockRules() []string {
	var rules []string
	for _, p := range v.policy.AllowedReadPaths {
		rules = append(rules, fmt.Sprintf("LANDLOCK_ACCESS_FS_READ:%s", p))
	}
	for _, p := range v.policy.AllowedWritePaths {
		rules = append(rules, fmt.Sprintf("LANDLOCK_ACCESS_FS_WRITE:%s", p))
	}
	return rules
}
