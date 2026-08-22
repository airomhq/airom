package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/approved"
)

func newApproveCmd() *cobra.Command {
	var scope string
	var maxTemp string
	var maxTokens string
	var ticket string

	cmd := &cobra.Command{
		Use:   "approve <purl>",
		Short: "Approve a component for use in the repository",
		Args:  exactArgs(1, "exactly one <purl>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			purl := args[0]
			wd, err := os.Getwd()
			if err != nil {
				return err
			}

			repoRoot := findRepoRoot(wd)

			manifest, err := approved.LoadManifest(repoRoot)
			if err != nil {
				return fmt.Errorf("failed to load manifest: %w", err)
			}
			if manifest == nil {
				manifest = &approved.Manifest{
					SchemaVersion: "1",
					Repo:          filepath.Base(repoRoot),
				}
			}

			userEmail := getUserEmail()

			approval := approved.ComponentApproval{
				PURL:       purl,
				ApprovedBy: userEmail,
				ApprovedAt: time.Now().UTC().Format(time.RFC3339),
				Ticket:     ticket,
			}

			if scope != "" {
				approval.Scope = []string{scope}
			}
			if maxTemp != "" || maxTokens != "" {
				approval.PermittedConfig = make(map[string]string)
				if maxTemp != "" {
					approval.PermittedConfig["max_temp"] = maxTemp
				}
				if maxTokens != "" {
					approval.PermittedConfig["max_tokens"] = maxTokens
				}
			}

			// Update if exists
			updated := false
			for i, a := range manifest.Approved {
				if a.PURL == purl {
					manifest.Approved[i] = approval
					updated = true
					break
				}
			}
			if !updated {
				manifest.Approved = append(manifest.Approved, approval)
			}

			if err := approved.SaveManifest(repoRoot, manifest); err != nil {
				return fmt.Errorf("failed to save manifest: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Approved component %s\n", purl)
			return nil
		},
	}

	cmd.Flags().StringVar(&scope, "scope", "", "Path glob restricting where this component is approved")
	cmd.Flags().StringVar(&maxTemp, "max-temp", "", "Maximum allowed temperature")
	cmd.Flags().StringVar(&maxTokens, "max-tokens", "", "Maximum allowed tokens")
	cmd.Flags().StringVar(&ticket, "ticket", "", "Ticket reference for the approval")

	return cmd
}

func findRepoRoot(wd string) string {
	curr := wd
	for {
		if _, err := os.Stat(filepath.Join(curr, ".git")); err == nil {
			return curr
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}
	return wd
}

func getUserEmail() string {
	out, err := exec.Command("git", "config", "user.email").Output()
	if err == nil {
		email := strings.TrimSpace(string(out))
		if email != "" {
			return email
		}
	}
	u, err := user.Current()
	if err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}
