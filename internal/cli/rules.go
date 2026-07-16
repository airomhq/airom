package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Roro1727/airom/internal/app"
	"github.com/Roro1727/airom/internal/ruleengine/ruletest"
)

// newRulesCmd is the rule-pack toolbox (docs/cli.md): inspect the effective
// ruleset and validate/run user packs without a Go toolchain.
func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect, lint, and test rule packs",
	}
	cmd.AddCommand(newRulesListCmd(), newRulesLintCmd(), newRulesTestCmd())
	return cmd
}

func newRulesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show the effective ruleset (embedded + --rules overlays), each rule with its layer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("determine working directory: %w", err)
			}
			cfg, err := buildConfig(cmd.Flags(), wd, app.SourceFS, ".")
			if err != nil {
				return err
			}
			rules, err := app.RulesList(cfg)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if len(rules) == 0 {
				fmt.Fprintln(w, "no rules in the effective set (no embedded packs and no --rules overlays)")
				return nil
			}
			fmt.Fprintf(w, "%-40s %-16s %-12s %s\n", "RULE ID", "KIND", "CONFIDENCE", "LAYER")
			for _, r := range rules {
				fmt.Fprintf(w, "%-40s %-16s %-12.2f %s\n", r.ID, r.Kind, r.Confidence, r.Layer)
			}
			fmt.Fprintf(w, "\n%d rule(s)\n", len(rules))
			return nil
		},
	}
}

func newRulesLintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lint <file>",
		Short: "Validate a rule pack against the full lint contract and its fixture coverage",
		Args:  exactArgs("exactly one <file>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := app.RulesLint(args[0])
			if err != nil {
				return &app.UsageError{Err: err}
			}
			return reportResult(cmd, args[0], report)
		},
	}
}

func newRulesTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <file>",
		Short: "Run a rule pack against its fixtures (no Go toolchain needed)",
		Args:  exactArgs("exactly one <file>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := app.RulesTest(args[0])
			if err != nil {
				return &app.UsageError{Err: err}
			}
			return reportResult(cmd, args[0], report)
		},
	}
}

// reportResult prints a ruletest report and returns a UsageError when the
// pack fails, so the command exits non-zero.
func reportResult(cmd *cobra.Command, path string, report *ruletest.Report) error {
	w := cmd.OutOrStdout()
	if report.OK() {
		fmt.Fprintf(w, "%s: OK (%d expectation(s) checked)\n", path, report.Expectations)
		return nil
	}
	for _, f := range report.Failures {
		fmt.Fprintf(w, "  %s:%d %s: %s\n", f.File, f.Line, f.RuleID, f.Reason)
	}
	for _, id := range report.RulesMissingPositive {
		fmt.Fprintf(w, "  rule %s: missing a positive fixture (# airom: %s)\n", id, id)
	}
	for _, id := range report.RulesMissingNegative {
		fmt.Fprintf(w, "  rule %s: missing a negative fixture (# airom-ok: %s)\n", id, id)
	}
	return &app.UsageError{Err: fmt.Errorf("%s: rule pack has failures", path)}
}
