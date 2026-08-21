# PRD-01: .airomapproved Governance Primitive & Shadow AI Detection

> **Status:** APPROVED FOR IMPLEMENTATION
> **Target Sprint:** Sprint 1 & Sprint 2 (Phase 1)
> **Target Package:** internal/approved/, internal/cli/, internal/assemble/
> **Owner:** Lead Go Systems Engineer

---

## 1. Problem & Objectives
- **Problem:** Developers install and call new AI models (e.g. OpenAI GPT-4o, Anthropic Claude 3.5, LangChain) in code without security/legal sign-off, creating immediate regulatory and data-leak liability ("Shadow AI").
- **Solution:** A git-tracked manifest (.airomapproved) in the repo root defining approved models, versions, path scopes, and parameter limits. The scanner flags unapproved components as SHADOW_AI_DETECTED with exit code 1 in CI.
- **Key Invariant:** Zero network requests required. Manifest signature validation is purely local SHA-256 HMAC.

---

## 2. Manifest Schema Specification (.airomapproved)

File location: <repo_root>/.airomapproved (YAML format)

`yaml
schema_version: "1.0"
repo: "github.com/acme-corp/loan-decisioning"
signature: "sha256:4f9a2c89b71e4d..." # HMAC over serialized components

approved:
  - purl: "pkg:pypi/openai@1.51.0"
    approved_by: "sarah.chen@acme-corp.com"
    approved_at: "2026-08-21T14:22:00Z"
    ticket: "SEC-402"
    scope:
      - "src/underwriting/**"
    permitted_config:
      temperature_max: "0.3"
      max_tokens_max: "2048"

deny:
  - purl: "pkg:pypi/langchain@0.2.16"
    reason: "Known CVE-2026-45134; upgrade to 0.3.30 required"

revocations: []
`

---

## 3. Go Data Structures & Interfaces

File: internal/approved/manifest.go

`go
package approved

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type ComponentApproval struct {
	PURL            string            yaml:"purl"
	ApprovedBy      string            yaml:"approved_by"
	ApprovedAt      time.Time         yaml:"approved_at"
	Ticket          string            yaml:"ticket,omitempty"
	Scope           []string          yaml:"scope"
	PermittedConfig map[string]string yaml:"permitted_config,omitempty"
	Reason          string            yaml:"reason,omitempty"
}

type ApprovedManifest struct {
	SchemaVersion string              yaml:"schema_version"
	Repo          string              yaml:"repo"
	Signature     string              yaml:"signature"
	Approved      []ComponentApproval yaml:"approved"
	Deny          []ComponentApproval yaml:"deny,omitempty"
	Revocations   []ComponentApproval yaml:"revocations,omitempty"
}

func LoadManifest(repoRoot string) (*ApprovedManifest, error) {
	path := filepath.Join(repoRoot, ".airomapproved")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read .airomapproved: %w", err)
	}

	var m ApprovedManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("malformed .airomapproved: %w", err)
	}
	return &m, nil
}

func (m *ApprovedManifest) IsApproved(purl string, filePath string) (bool, string, string) {
	if m == nil {
		return true, "unmanaged", ""
	}

	for _, d := range m.Deny {
		if matchPURL(d.PURL, purl) {
			return false, "denied", d.Reason
		}
	}

	for _, a := range m.Approved {
		if matchPURL(a.PURL, purl) {
			if len(a.Scope) == 0 || matchScope(a.Scope, filePath) {
				return true, "approved", ""
			}
			return false, "scope_mismatch", fmt.Sprintf("file %s outside approved scope %v", filePath, a.Scope)
		}
	}

	return false, "unapproved", "component not listed in .airomapproved"
}
`

---

## 4. Acceptance Criteria & Test Cases
1. TestLoadManifest_MissingFile: returns 
il, nil without error.
2. TestIsApproved_Match: returns 	rue, "approved" when PURL matches.
3. TestIsApproved_ScopeMismatch: returns alse, "scope_mismatch" when file path is outside glob.
4. TestIsApproved_Deny: returns alse, "denied" when listed in deny list.
5. Golden test: Scanning 	estdata/fixtures/approved_project/ flags Shadow AI with exit code 1.
