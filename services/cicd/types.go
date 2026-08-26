// Package cicd generates automated CI/CD pipeline actions and pre-commit hooks
// enforcing AI governance gates and AIBOM generation across GitHub Actions, GitLab CI, and Git hooks.
package cicd

import (
	"time"
)

// Platform specifies the CI/CD pipeline runner.
type Platform string

const (
	PlatformGitHubActions Platform = "GITHUB_ACTIONS"
	PlatformGitLabCI      Platform = "GITLAB_CI"
	PlatformPreCommit     Platform = "PRE_COMMIT_HOOK"
)

// PipelineSpec models the user's required CI/CD governance policies.
type PipelineSpec struct {
	Platform     Platform `json:"platform"`
	Framework    string   `json:"framework"` // e.g. "eu-ai-act", "colorado-ai-act"
	FailOnGaps   bool     `json:"failOnGaps"`
	GeneratePDF  bool     `json:"generatePdf"`
	AutoApprove  bool     `json:"autoApprove"`
	TargetBranch string   `json:"targetBranch"` // e.g. "main"
}

// WorkflowResult contains the compiled workflow file and instructions.
type WorkflowResult struct {
	Platform    Platform  `json:"platform"`
	FilePath    string    `json:"filePath"` // e.g. ".github/workflows/airom.yml"
	Content     string    `json:"content"`
	GeneratedAt time.Time `json:"generatedAt"`
}
