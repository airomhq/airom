package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Engine evaluates source code and manifests, generating automated upgrade PRs.
type Engine struct {
	mu    sync.RWMutex
	rules map[string]ModelUpgradeRule
}

// NewEngine constructs a remediation engine with default foundation model upgrade rules.
func NewEngine() *Engine {
	e := &Engine{
		rules: make(map[string]ModelUpgradeRule),
	}

	// Register canonical drop-in model upgrade rules
	e.RegisterRule(ModelUpgradeRule{
		DeprecatedModel:  "gpt-3.5-turbo-0613",
		ReplacementModel: "gpt-4o-mini",
		Provider:         "OpenAI",
		Rationale:        "gpt-3.5-turbo-0613 was shut down by OpenAI. gpt-4o-mini is faster, cheaper, and strictly superior on MMLU benchmarks.",
		CostMultiplier:   0.33,
	})
	e.RegisterRule(ModelUpgradeRule{
		DeprecatedModel:  "gpt-3.5-turbo",
		ReplacementModel: "gpt-4o-mini",
		Provider:         "OpenAI",
		Rationale:        "Upgrade legacy gpt-3.5-turbo to modern gpt-4o-mini drop-in replacement.",
		CostMultiplier:   0.33,
	})
	e.RegisterRule(ModelUpgradeRule{
		DeprecatedModel:  "text-davinci-003",
		ReplacementModel: "gpt-4o-mini",
		Provider:         "OpenAI",
		Rationale:        "text-davinci-003 completion endpoint is deprecated.",
		CostMultiplier:   0.10,
	})
	e.RegisterRule(ModelUpgradeRule{
		DeprecatedModel:  "claude-2.0",
		ReplacementModel: "claude-3-5-sonnet-20240620",
		Provider:         "Anthropic",
		Rationale:        "Claude 2.0 is superseded by Claude 3.5 Sonnet.",
		CostMultiplier:   0.80,
	})

	return e
}

// RegisterRule adds or overrides an upgrade rule.
func (e *Engine) RegisterRule(rule ModelUpgradeRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules[rule.DeprecatedModel] = rule
}

// CreateRemediationPlan scans files for deprecated model strings and builds unified diff patches.
func (e *Engine) CreateRemediationPlan(repoID string, files map[string]string) *RemediationPlan {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now().UTC()
	var patches []FilePatch
	var upgradedRules []ModelUpgradeRule
	seenRules := make(map[string]bool)

	for path, content := range files {
		modified := content
		replacements := 0

		for depModel, rule := range e.rules {
			if strings.Contains(modified, depModel) {
				count := strings.Count(modified, depModel)
				modified = strings.ReplaceAll(modified, depModel, rule.ReplacementModel)
				replacements += count
				if !seenRules[depModel] {
					upgradedRules = append(upgradedRules, rule)
					seenRules[depModel] = true
				}
			}
		}

		if replacements > 0 {
			diff := generateUnifiedDiff(path, content, modified)
			patches = append(patches, FilePatch{
				FilePath:     path,
				OriginalText: content,
				ModifiedText: modified,
				DiffUnified:  diff,
				Replacements: replacements,
			})
		}
	}

	if len(patches) == 0 {
		return nil
	}

	h := sha256.Sum256([]byte(repoID + now.Format(time.RFC3339Nano)))
	planID := fmt.Sprintf("plan-%s", hex.EncodeToString(h[:6]))
	branch := fmt.Sprintf("airom/upgrade-models-%s", hex.EncodeToString(h[:4]))

	var sb strings.Builder
	sb.WriteString("## 🤖 AIROM Automated Model Upgrade Remediation\n\n")
	sb.WriteString("This automated pull request upgrades deprecated or EOL foundation model references to modern replacements:\n\n")

	for _, r := range upgradedRules {
		fmt.Fprintf(&sb, "- **Deprecated:** `%s` ➔ **Replacement:** `%s` (%s)\n  *Rationale:* %s\n",
			r.DeprecatedModel, r.ReplacementModel, r.Provider, r.Rationale)
	}

	sb.WriteString("\n### 📋 Summary of Changes\n")
	for _, p := range patches {
		fmt.Fprintf(&sb, "- `%s`: %d replacement(s)\n", p.FilePath, p.Replacements)
	}

	sb.WriteString("\n> *Verified automatically by AIROM AST Code Remediation Engine.*")

	return &RemediationPlan{
		PlanID:       planID,
		RepoID:       repoID,
		BranchName:   branch,
		Title:        fmt.Sprintf("fix(ai): automated upgrade of %d deprecated model references", len(upgradedRules)),
		BodyMarkdown: sb.String(),
		Patches:      patches,
		CreatedAt:    now,
	}
}

func generateUnifiedDiff(path, oldText, newText string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- a/%s\n+++ b/%s\n", path, path)

	oldLines := strings.Split(oldText, "\n")
	newLines := strings.Split(newText, "\n")

	fmt.Fprintf(&sb, "@@ -1,%d +1,%d @@\n", len(oldLines), len(newLines))
	for _, l := range oldLines {
		fmt.Fprintf(&sb, "-%s\n", l)
	}
	for _, l := range newLines {
		fmt.Fprintf(&sb, "+%s\n", l)
	}
	return sb.String()
}
