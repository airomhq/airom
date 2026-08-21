package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/approved"
)

func newRevokeCmd() *cobra.Command {
	var reason string

	cmd := &cobra.Command{
		Use:   "revoke <purl>",
		Short: "Revoke a component's approval",
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
				return fmt.Errorf("no manifest found; nothing to revoke")
			}

			var toRevoke *approved.ComponentApproval
			var newApproved []approved.ComponentApproval

			for _, a := range manifest.Approved {
				if a.PURL == purl {
					toRevoke = &a
				} else {
					newApproved = append(newApproved, a)
				}
			}

			if toRevoke == nil {
				return fmt.Errorf("component %s is not in the approved list", purl)
			}

			manifest.Approved = newApproved

			userEmail := getUserEmail()
			revocation := *toRevoke
			revocation.ApprovedBy = userEmail
			revocation.ApprovedAt = time.Now().UTC().Format(time.RFC3339)
			revocation.Reason = reason

			manifest.Revocations = append(manifest.Revocations, revocation)

			if err := approved.SaveManifest(repoRoot, manifest); err != nil {
				return fmt.Errorf("failed to save manifest: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Revoked component %s\n", purl)
			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "", "Reason for revocation")

	return cmd
}
