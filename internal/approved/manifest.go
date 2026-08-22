// Package approved manages .airomapproved manifests for AI component governance.
package approved

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ComponentApproval represents an approved or denied component entry in .airomapproved.
type ComponentApproval struct {
	PURL            string            `yaml:"purl"`
	ApprovedBy      string            `yaml:"approved_by,omitempty"`
	ApprovedAt      string            `yaml:"approved_at,omitempty"`
	Ticket          string            `yaml:"ticket,omitempty"`
	Scope           []string          `yaml:"scope,omitempty"`
	PermittedConfig map[string]string `yaml:"permitted_config,omitempty"`
	Reason          string            `yaml:"reason,omitempty"`
}

// ApprovedManifest represents the parsed .airomapproved repository manifest.
type ApprovedManifest struct {
	SchemaVersion string              `yaml:"schema_version"`
	Repo          string              `yaml:"repo"`
	Signature     string              `yaml:"signature"`
	Approved      []ComponentApproval `yaml:"approved,omitempty"`
	Deny          []ComponentApproval `yaml:"deny,omitempty"`
	Revocations   []ComponentApproval `yaml:"revocations,omitempty"`
}

// LoadManifest reads and parses .airomapproved from the given repository root directory.
func LoadManifest(repoRoot string) (*ApprovedManifest, error) {
	manifestPath := filepath.Join(repoRoot, ".airomapproved")
	data, err := os.ReadFile(manifestPath) // #nosec G304 -- manifest path constructed from repoRoot
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // graceful fallback
		}
		return nil, err
	}

	var m ApprovedManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	// Verify signature integrity if a signature exists
	if m.Signature != "" {
		expected := ComputeSignature(&m)
		if expected != "" && m.Signature != expected {
			return &m, fmt.Errorf("tampered manifest signature: expected %s, got %s", expected, m.Signature)
		}
	}

	return &m, nil
}

// ComputeSignature calculates the HMAC-SHA256 signature for the manifest.
func ComputeSignature(m *ApprovedManifest) string {
	clone := *m
	clone.Signature = ""
	data, err := yaml.Marshal(clone)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, []byte("airom"))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// SaveManifest serializes and writes the manifest to .airomapproved in repoRoot.
func SaveManifest(repoRoot string, m *ApprovedManifest) error {
	m.Signature = ComputeSignature(m)
	data, err := yaml.Marshal(m)
	if err != nil {
		return err
	}

	manifestPath := filepath.Join(repoRoot, ".airomapproved")
	tmpPath := manifestPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}

	return os.Rename(tmpPath, manifestPath)
}

// IsApproved checks whether a given PURL and file path are approved according to the manifest.
func (m *ApprovedManifest) IsApproved(purl string, filePath string) (bool, string, string) {
	for _, deny := range m.Deny {
		if matchPURL(deny.PURL, purl) {
			if len(deny.Scope) == 0 || matchScope(deny.Scope, filePath) {
				reason := deny.Reason
				if reason == "" {
					reason = "Explicitly denied in .airomapproved"
				}
				return false, "denied", reason
			}
		}
	}

	var foundApproved bool
	var scopeMismatch bool

	for _, app := range m.Approved {
		if matchPURL(app.PURL, purl) {
			foundApproved = true
			if len(app.Scope) == 0 || matchScope(app.Scope, filePath) {
				return true, "approved", app.Reason
			}
			scopeMismatch = true
		}
	}

	if scopeMismatch {
		return false, "scope_mismatch", "PURL approved but file outside scope"
	}

	if foundApproved {
		return false, "scope_mismatch", "PURL approved but file outside scope"
	}

	return false, "unapproved", "Component not found in approved list"
}

func matchPURL(pattern, purl string) bool {
	if pattern == purl {
		return true
	}
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, purl)
		if matched {
			return true
		}
		if ok, _ := filepath.Match(strings.ToLower(pattern), strings.ToLower(purl)); ok {
			return true
		}
	}
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(purl, pattern)
	}
	// Case-insensitive exact match
	if strings.EqualFold(pattern, purl) {
		return true
	}
	return false
}

func matchScope(scopes []string, filePath string) bool {
	filePath = filepath.ToSlash(filePath)
	for _, scope := range scopes {
		scope = filepath.ToSlash(scope)
		// Try direct match
		if matched, _ := filepath.Match(scope, filePath); matched {
			return true
		}
		// Handle ** recursion
		if strings.Contains(scope, "**") {
			prefix := strings.TrimSuffix(scope, "/**")
			prefix = strings.TrimSuffix(prefix, "/*")
			if prefix == "" || prefix == "." || strings.HasPrefix(filePath, prefix+"/") || filePath == prefix {
				return true
			}
		}
		if strings.HasPrefix(filePath, strings.TrimSuffix(scope, "*")) {
			return true
		}
	}
	return false
}

// CheckConfigDrift validates if the runtime configuration matches permitted thresholds.
func (m *ApprovedManifest) CheckConfigDrift(purl string, params map[string]string) (bool, string, string) {
	if m == nil {
		return false, "", ""
	}
	for _, app := range m.Approved {
		if matchPURL(app.PURL, purl) {
			if len(app.PermittedConfig) == 0 {
				continue
			}

			if maxTempStr, ok := app.PermittedConfig["max_temp"]; ok {
				if tempStr, ok := params["temperature"]; ok {
					if maxTemp, err1 := strconv.ParseFloat(maxTempStr, 64); err1 == nil {
						if temp, err2 := strconv.ParseFloat(tempStr, 64); err2 == nil {
							if temp > maxTemp {
								return true, "config_drift", fmt.Sprintf("temperature %s exceeds approved maximum %s", tempStr, maxTempStr)
							}
						}
					}
				}
			}

			if maxTokensStr, ok := app.PermittedConfig["max_tokens"]; ok {
				if tokensStr, ok := params["max_tokens"]; ok {
					if maxTokens, err1 := strconv.ParseInt(maxTokensStr, 10, 64); err1 == nil {
						if tokens, err2 := strconv.ParseInt(tokensStr, 10, 64); err2 == nil {
							if tokens > maxTokens {
								return true, "config_drift", fmt.Sprintf("max_tokens %s exceeds approved maximum %s", tokensStr, maxTokensStr)
							}
						}
					}
				}
			}
		}
	}
	return false, "", ""
}
