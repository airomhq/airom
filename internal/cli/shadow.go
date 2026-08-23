package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/shadowai"
)

func newShadowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "shadow",
		GroupID: groupCompliance,
		Short:   "Discover, inventory, and govern unauthorized third-party SaaS AI tools and API keys",
		Long: `Shadow AI & SaaS Connector Discovery Agent.
Discovers undeclared SaaS AI platforms (OpenAI, Anthropic, Cursor, Copilot, Notion AI, Slack AI, Perplexity)
in codebases, IDE configs, environment secrets, and CI/CD pipelines.`,
	}

	cmd.AddCommand(newShadowScanCmd())

	return cmd
}

func newShadowScanCmd() *cobra.Command {
	var (
		scanPath string
		orgID    string
		asJSON   bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory or codebase for undeclared Shadow AI assets and tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				scanPath = args[0]
			}
			if scanPath == "" {
				scanPath = "."
			}

			detector := shadowai.NewShadowAIDetector()
			var entries []shadowai.FileEntry

			// Walk files in scanPath
			_ = filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					if d != nil && d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor") {
						return filepath.SkipDir
					}
					return nil
				}

				// Only read text / config files < 512KB
				info, err := d.Info()
				if err != nil || info.Size() > 512*1024 {
					return nil
				}

				relPath, _ := filepath.Rel(scanPath, path)
				if relPath == "" {
					relPath = path
				}

				contentBytes, err := os.ReadFile(path)
				if err != nil {
					return nil
				}

				entries = append(entries, shadowai.FileEntry{
					Path:    strings.ReplaceAll(relPath, "\\", "/"),
					Content: string(contentBytes),
				})
				return nil
			})

			inventory, err := detector.ScanFiles(entries, shadowai.DetectorOptions{
				OrganizationID: orgID,
			})
			if err != nil {
				return fmt.Errorf("shadow AI scan failed: %w", err)
			}

			if asJSON {
				data, err := json.MarshalIndent(inventory, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			fmt.Fprint(cmd.OutOrStdout(), shadowai.RenderInventoryDashboard(inventory))
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&scanPath, "path", "p", ".", "Root directory to scan for shadow AI tools")
	flags.StringVar(&orgID, "org", "org_enterprise", "Enterprise organization ID")
	flags.BoolVar(&asJSON, "json", false, "Output shadow AI inventory as JSON")

	return cmd
}
