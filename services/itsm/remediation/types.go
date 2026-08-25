// Package remediation generates automated code and manifest upgrade pull requests
// for retired/EOL foundation models, deprecated SDKs, and vulnerable dependencies.
package remediation

import (
	"time"
)

// ModelUpgradeRule maps a deprecated or EOL model to its recommended drop-in replacement.
type ModelUpgradeRule struct {
	DeprecatedModel  string  `json:"deprecatedModel"`  // e.g. "gpt-3.5-turbo-0613"
	ReplacementModel string  `json:"replacementModel"` // e.g. "gpt-4o-mini"
	Provider         string  `json:"provider"`         // e.g. "OpenAI"
	Rationale        string  `json:"rationale"`        // e.g. "Model retired; gpt-4o-mini offers 60% lower cost and higher benchmark accuracy."
	CostMultiplier   float64 `json:"costMultiplier"`   // e.g. 0.40
}

// FilePatch contains the original and modified content for a specific file.
type FilePatch struct {
	FilePath     string `json:"filePath"`
	OriginalText string `json:"originalText"`
	ModifiedText string `json:"modifiedText"`
	DiffUnified  string `json:"diffUnified"`
	Replacements int    `json:"replacements"`
}

// RemediationPlan aggregates all generated file patches into a unified Pull Request specification.
type RemediationPlan struct {
	PlanID       string      `json:"planId"`
	RepoID       string      `json:"repoId"`
	BranchName   string      `json:"branchName"`   // e.g. "airom/fix-eol-gpt35"
	Title        string      `json:"title"`        // e.g. "fix(ai): upgrade deprecated gpt-3.5-turbo to gpt-4o-mini"
	BodyMarkdown string      `json:"bodyMarkdown"` // PR description with compliance and benchmark justification
	Patches      []FilePatch `json:"patches"`
	CreatedAt    time.Time   `json:"createdAt"`
}
