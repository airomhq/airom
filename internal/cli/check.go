package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/app"
	"github.com/airomhq/airom/internal/approved"
	"github.com/airomhq/airom/internal/source"
	"github.com/airomhq/airom/pkg/airom"
)

func newCheckCmd() *cobra.Command {
	var isApproved bool

	cmd := &cobra.Command{
		Use:     "check <target>",
		GroupID: groupScan,
		Short:   "Check governance status and fail if unapproved components exist",
		Args:    exactArgs(1, "exactly one <target>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, target, err := source.DetectTarget(args[0])
			if err != nil {
				return &app.UsageError{Err: err}
			}
			var src app.SourceKind
			switch kind {
			case source.TargetDir:
				src = app.SourceFS
			case source.TargetRepo:
				src = app.SourceRepo
			case source.TargetImage:
				src = app.SourceImage
			}

			wd, err := os.Getwd()
			if err != nil {
				return err
			}

			if !isApproved {
				return fmt.Errorf("check command currently requires --approved flag")
			}

			repoRoot := target
			if stat, err := os.Stat(target); err == nil && !stat.IsDir() {
				repoRoot = filepath.Dir(target)
			}
			if _, err := os.Stat(filepath.Join(repoRoot, ".airomapproved")); err != nil {
				repoRoot = findRepoRoot(repoRoot)
			}

			manifest, err := approved.LoadManifest(repoRoot)
			if err != nil {
				return fmt.Errorf("failed to load manifest: %w", err)
			}
			if manifest == nil {
				manifest = &approved.ApprovedManifest{}
			}

			cfg, err := buildConfig(cmd.Flags(), wd, src, target)
			if err != nil {
				return err
			}

			tmpFile, err := os.CreateTemp("", "airom-check-*.json")
			if err != nil {
				return err
			}
			tmpPath := tmpFile.Name()
			tmpFile.Close()
			defer os.Remove(tmpPath)

			cfg.Outputs = []app.OutputSpec{{Format: app.FormatJSON, Path: tmpPath}}
			cfg.Quiet = true 

			if err := runScan(cmd.Context(), cfg); err != nil {
				return err
			}

			data, err := os.ReadFile(tmpPath)
			if err != nil {
				return fmt.Errorf("failed to read scan results: %w", err)
			}

			var inv airom.Inventory
			if err := json.Unmarshal(data, &inv); err != nil {
				return fmt.Errorf("failed to parse scan results: %w", err)
			}

			unapprovedCount := 0
			for _, comp := range inv.Components {
				// Skip pure metadata, root application containers, and config kinds
				if comp.Kind == "ai-config" || comp.Kind == "application" || comp.Kind == "project" || comp.Kind == "app" || comp.Kind == "container" || comp.Kind == "repo" || comp.Kind == "dataset" {
					continue
				}

				purl := comp.PURL
				if purl == "" {
					purl = comp.Name
				}
				
				filePath := ""
				if len(comp.Evidence.Occurrences) > 0 {
					filePath = comp.Evidence.Occurrences[0].Location.Path
				}
				// We assume path is relative to repoRoot for matching
				if filepath.IsAbs(filePath) {
					rel, err := filepath.Rel(repoRoot, filePath)
					if err == nil {
						filePath = rel
					}
				}

				// Check both PURL and Name
				approvedStatus, statusType, reason := manifest.IsApproved(purl, filePath)
				if !approvedStatus && comp.Name != "" && comp.Name != purl {
					nameApproved, nameStatus, nameReason := manifest.IsApproved(comp.Name, filePath)
					if statusType == "denied" {
						// Keep explicit denial priority
					} else if nameStatus == "denied" {
						approvedStatus, statusType, reason = false, nameStatus, nameReason
					} else if nameApproved {
						approvedStatus, statusType, reason = nameApproved, nameStatus, nameReason
					}
				}

				if !approvedStatus {
					fmt.Fprintf(cmd.ErrOrStderr(), "Unapproved component found: %s (Status: %s, Reason: %s)\n", purl, statusType, reason)
					unapprovedCount++
				}
			}

			if unapprovedCount > 0 {
				return &app.PolicyExit{Code: 1}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Governance check passed. All components approved.\n")
			return nil
		},
	}

	cmd.Flags().BoolVar(&isApproved, "approved", false, "check governance status and fail if unapproved components exist")

	return cmd
}
