package approved

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type ComponentApproval struct {
	PURL           string            `yaml:"purl"`
	ApprovedBy     string            `yaml:"approved_by,omitempty"`
	ApprovedAt     string            `yaml:"approved_at,omitempty"`
	Ticket         string            `yaml:"ticket,omitempty"`
	Scope          []string          `yaml:"scope,omitempty"`
	PermittedConfig map[string]string `yaml:"permitted_config,omitempty"`
	Reason         string            `yaml:"reason,omitempty"`
}

type ApprovedManifest struct {
	SchemaVersion string              `yaml:"schema_version"`
	Repo          string              `yaml:"repo"`
	Signature     string              `yaml:"signature"`
	Approved      []ComponentApproval `yaml:"approved,omitempty"`
	Deny          []ComponentApproval `yaml:"deny,omitempty"`
	Revocations   []ComponentApproval `yaml:"revocations,omitempty"`
}

func LoadManifest(repoRoot string) (*ApprovedManifest, error) {
	manifestPath := filepath.Join(repoRoot, ".airomapproved")
	data, err := os.ReadFile(manifestPath)
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

	return &m, nil
}

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

func SaveManifest(repoRoot string, m *ApprovedManifest) error {
	m.Signature = ComputeSignature(m)
	data, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	
	manifestPath := filepath.Join(repoRoot, ".airomapproved")
	tmpPath := manifestPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	
	return os.Rename(tmpPath, manifestPath)
}

func (m *ApprovedManifest) IsApproved(purl string, filePath string) (bool, string, string) {
	for _, deny := range m.Deny {
		if matchPURL(deny.PURL, purl) {
			if len(deny.Scope) == 0 || matchScope(deny.Scope, filePath) {
				return false, "denied", deny.Reason
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
