package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/regwatch"
)

func newRegWatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "regwatch",
		GroupID: groupDev,
		Short:   "AIROM RegWatch Legislative Intelligence & Statutory Delta Engine",
		Long: `Monitor live legislative feeds, state regulatory bulletins, and global AI statutory changes.
Detect breaking statutory obligations, semantic clauses deltas, and automated rulepack update alerts.`,
	}

	cmd.AddCommand(
		newRegWatchCheckCmd(),
		newRegWatchDiffCmd(),
		newRegWatchFeedCmd(),
	)

	return cmd
}

func newRegWatchCheckCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "check [jurisdiction]",
		Short: "Check live regulatory feeds for pending or enacted statutory changes",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc := regwatch.NewService(regwatch.DefaultScraperConfig())
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			w := cmd.OutOrStdout()

			if len(args) == 1 {
				j := regwatch.Jurisdiction(strings.ToUpper(args[0]))
				diff, alert, err := svc.CheckJurisdiction(ctx, j)
				if err != nil {
					return err
				}

				if jsonOutput {
					enc := json.NewEncoder(w)
					enc.SetIndent("", "  ")
					return enc.Encode(map[string]interface{}{
						"diff":  diff,
						"alert": alert,
					})
				}

				fmt.Fprintf(w, "Jurisdiction: %s\n", diff.Jurisdiction)
				fmt.Fprintf(w, "Status:       %s\n", diff.Summary)
				fmt.Fprintf(w, "Impact:       %s\n", diff.MaxSeverity)
				if alert != nil {
					fmt.Fprintf(w, "Action:       %s\n", alert.ActionRequired)
				}
				return nil
			}

			diffs, alerts, err := svc.CheckAllJurisdictions(ctx)
			if err != nil {
				return err
			}

			if jsonOutput {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]interface{}{
					"diffs":  diffs,
					"alerts": alerts,
				})
			}

			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "JURISDICTION\tTITLE\tSEVERITY\tSTATUS\tIMPACTED RULEPACKS")
			fmt.Fprintln(tw, "────────────\t─────\t────────\t──────\t──────────────────")

			for _, d := range diffs {
				doc, _ := svc.GetCachedDocument(d.Jurisdiction)
				status := "SYNCHRONIZED"
				if d.HasChanges {
					status = "DELTA DETECTED"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					d.Jurisdiction,
					truncate(doc.Title, 40),
					d.MaxSeverity,
					status,
					strings.Join(d.ImpactedRulepacks, ", "),
				)
			}
			_ = tw.Flush()

			if len(alerts) > 0 {
				fmt.Fprintf(w, "\n⚠️  %d Active Regulatory Alert(s) Generated:\n", len(alerts))
				for _, a := range alerts {
					fmt.Fprintf(w, " - [%s] %s (%s): %s\n", a.Severity, a.Title, a.Jurisdiction, a.ActionRequired)
				}
			} else {
				fmt.Fprintln(w, "\n✅ All local rulepacks and compliance policies are 100% synchronized with global statutory feeds.")
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output results in JSON format")
	return cmd
}

func newRegWatchDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <jurisdiction>",
		Short: "Display semantic clause deltas for a specific jurisdiction",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			j := regwatch.Jurisdiction(strings.ToUpper(args[0]))
			svc := regwatch.NewService(regwatch.DefaultScraperConfig())
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			diff, _, err := svc.CheckJurisdiction(ctx, j)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "=================================================================\n")
			fmt.Fprintf(w, "  AIROM RegWatch Statutory Diff: %s\n", diff.Jurisdiction)
			fmt.Fprintf(w, "=================================================================\n")
			fmt.Fprintf(w, "Old Version: %s | New Version: %s | Max Severity: %s\n\n",
				diff.OldVersion, diff.NewVersion, diff.MaxSeverity)

			if !diff.HasChanges {
				fmt.Fprintln(w, "No statutory modifications detected. Baseline is current.")
				return nil
			}

			for _, delta := range diff.SectionDeltas {
				fmt.Fprintf(w, "[%s] Section %s — %s\n", delta.Severity, delta.SectionID, delta.ChangeType)
				fmt.Fprintf(w, "Summary: %s\n", delta.DiffSummary)
				if delta.OldContent != "" {
					fmt.Fprintf(w, "[-] Old: %s\n", delta.OldContent)
				}
				if delta.NewContent != "" {
					fmt.Fprintf(w, "[+] New: %s\n", delta.NewContent)
				}
				fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────")
			}

			return nil
		},
	}
}

func newRegWatchFeedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "feed",
		Short: "List all active monitored legislative feeds and statutory baselines",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc := regwatch.NewService(regwatch.DefaultScraperConfig())
			w := cmd.OutOrStdout()

			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "JURISDICTION\tSTATUTE / REGULATION TITLE\tVERSION\tEFFECTIVE DATE\tSOURCE URL")
			fmt.Fprintln(tw, "────────────\t──────────────────────────\t───────\t──────────────\t──────────")

			jurisdictions := []regwatch.Jurisdiction{
				regwatch.JurisdictionColorado,
				regwatch.JurisdictionCalifornia,
				regwatch.JurisdictionNYC,
				regwatch.JurisdictionEU,
				regwatch.JurisdictionIllinois,
				regwatch.JurisdictionTexas,
				regwatch.JurisdictionVirginia,
				regwatch.JurisdictionUSFederal,
			}

			for _, j := range jurisdictions {
				if doc, found := svc.GetCachedDocument(j); found {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
						doc.Jurisdiction,
						truncate(doc.Title, 45),
						doc.Version,
						doc.EffectiveDate.Format("2006-01-02"),
						doc.SourceURL,
					)
				}
			}
			return tw.Flush()
		},
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
