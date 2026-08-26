package cicd

import (
	"fmt"
	"sync"
	"time"
)

// Compiler synthesizes robust CI/CD configuration files.
type Compiler struct {
	mu sync.RWMutex
}

// NewCompiler constructs a new CI/CD workflow compiler.
func NewCompiler() *Compiler {
	return &Compiler{}
}

// Compile generates standard CI/CD workflow files based on user policy specs.
func (c *Compiler) Compile(spec PipelineSpec) WorkflowResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now().UTC()
	if spec.Framework == "" {
		spec.Framework = "colorado-ai-act"
	}
	if spec.TargetBranch == "" {
		spec.TargetBranch = "main"
	}

	var filePath string
	var content string

	switch spec.Platform {
	case PlatformGitHubActions:
		filePath = ".github/workflows/airom-governance.yml"
		failFlag := ""
		if spec.FailOnGaps {
			failFlag = " --fail-on compliance:gap"
		}
		pdfStep := ""
		if spec.GeneratePDF {
			pdfStep = fmt.Sprintf("\n      - name: Generate Executive Compliance PDF Dossier\n        run: ./airom report --framework %s --type pdf --out aibom-compliance.pdf .", spec.Framework)
		}

		content = fmt.Sprintf(`name: AIROM AI Governance & AIBOM Gate
on:
  push:
    branches: [ "%s" ]
  pull_request:
    branches: [ "%s" ]

jobs:
  airom-audit:
    name: AI Bill of Materials & Statutory Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Go toolchain
        uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Install AIROM Governance Scanner
        run: go install github.com/airomhq/airom/cmd/airom@latest

      - name: Execute AIBOM Discovery & %s Compliance Check
        run: airom compliance --framework %s%s .%s
`, spec.TargetBranch, spec.TargetBranch, spec.Framework, spec.Framework, failFlag, pdfStep)

	case PlatformGitLabCI:
		filePath = ".gitlab-ci.yml"
		content = fmt.Sprintf(`stages:
  - governance

airom_compliance_gate:
  stage: governance
  image: golang:1.24-alpine
  script:
    - go install github.com/airomhq/airom/cmd/airom@latest
    - airom compliance --framework %s .
`, spec.Framework)

	default: // PlatformPreCommit
		filePath = ".git/hooks/pre-commit"
		content = fmt.Sprintf(`#!/bin/sh
# AIROM Pre-Commit Statutory Safety Check
echo "🔍 Running AIROM AIBOM statutory pre-commit scan..."
airom compliance --framework %s --fail-on-gap .
if [ $? -ne 0 ]; then
  echo "❌ AIROM Gate: Commit rejected due to unresolved AI compliance gaps."
  exit 1
fi
echo "✅ AIROM Gate: All AI assets conformant."
exit 0
`, spec.Framework)
	}

	return WorkflowResult{
		Platform:    spec.Platform,
		FilePath:    filePath,
		Content:     content,
		GeneratedAt: now,
	}
}
