package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/cicd"
)

func newCICDCmd() *cobra.Command {
	var platformStr string
	var framework string
	var failOnGaps bool
	var generatePDF bool
	var branch string
	var outFile string

	cmd := &cobra.Command{
		Use:     "cicd",
		GroupID: groupInspect,
		Short:   "Generate automated CI/CD pipeline actions and git pre-commit hooks",
		Long: `Synthesize production-grade, zero-dependency CI/CD workflows for GitHub Actions,
GitLab CI, and Git pre-commit hooks that automatically discover AI assets, gate PRs
against statutory compliance gaps, and generate executive PDF compliance scorecards.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			platform := cicd.PlatformGitHubActions
			switch platformStr {
			case "gitlab":
				platform = cicd.PlatformGitLabCI
			case "precommit", "pre-commit", "hook":
				platform = cicd.PlatformPreCommit
			default:
				platform = cicd.PlatformGitHubActions
			}

			if framework == "" {
				framework = "colorado-ai-act"
			}
			if branch == "" {
				branch = "main"
			}

			compiler := cicd.NewCompiler()
			res := compiler.Compile(cicd.PipelineSpec{
				Platform:     platform,
				Framework:    framework,
				FailOnGaps:   failOnGaps,
				GeneratePDF:  generatePDF,
				TargetBranch: branch,
			})

			targetPath := res.FilePath
			if outFile != "" {
				targetPath = outFile
			}

			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil && filepath.Dir(targetPath) != "." {
				return fmt.Errorf("create parent directory: %w", err)
			}

			if err := os.WriteFile(targetPath, []byte(res.Content), 0o755); err != nil {
				return fmt.Errorf("write workflow file: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Synthesized %s Governance Pipeline: %s\n", platform, targetPath)
			fmt.Fprintf(cmd.OutOrStdout(), "   Framework:    %s\n", framework)
			fmt.Fprintf(cmd.OutOrStdout(), "   Target Branch:%s\n", branch)
			return nil
		},
	}

	cmd.Flags().StringVarP(&platformStr, "platform", "p", "github", "CI platform (github, gitlab, pre-commit)")
	cmd.Flags().StringVarP(&framework, "framework", "f", "colorado-ai-act", "governance framework to enforce (colorado-ai-act, eu-ai-act, ca-ab2013)")
	cmd.Flags().BoolVar(&failOnGaps, "fail-on-gaps", true, "fail the CI pipeline if statutory compliance gaps exist")
	cmd.Flags().BoolVar(&generatePDF, "generate-pdf", true, "generate executive PDF report as a build artifact")
	cmd.Flags().StringVarP(&branch, "branch", "b", "main", "target branch for pull requests")
	cmd.Flags().StringVarP(&outFile, "out", "O", "", "custom output file path (default: .github/workflows/airom-governance.yml)")

	return cmd
}
