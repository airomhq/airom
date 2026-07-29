package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/app"
	"github.com/airomhq/airom/internal/ruleengine/ruletest"
)

// newRulesCmd is the rule-pack toolbox (docs/cli.md): inspect the effective
// ruleset and validate/run user packs without a Go toolchain.
func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rules",
		GroupID: groupInspect,
		Short:   "Inspect, lint, and test rule packs",
	}
	cmd.AddCommand(newRulesListCmd(), newRulesLintCmd(), newRulesTestCmd(), newRulesUpdateCmd())
	return cmd
}

// newRulesUpdateCmd fetches a signed rule bundle from the airom-rules release
// channel into the cache; scans then prefer it over the built-in packs. This is
// the only rules subcommand that touches the network (Model B).
func newRulesUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [version]",
		Short: "Fetch, verify (ed25519), and cache a signed rule bundle from airom-rules",
		Args:  maxArgs(1, "an optional <version> (default: the latest release)"),
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("determine working directory: %w", err)
			}
			cfg, err := buildConfig(cmd.Flags(), wd, app.SourceFS, ".")
			if err != nil {
				return err
			}
			version := ""
			if len(args) == 1 {
				version = args[0]
			}
			res, err := app.RulesUpdate(cmd.Context(), cfg, version)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Installed rule bundle %s — %d pack(s), %d rule(s)\n", res.Version, res.PackCount, res.RuleCount)
			fmt.Fprintf(w, "  sha256: %s\n", res.SHA256)
			fmt.Fprintf(w, "  cache:  %s\n", res.Path)
			fmt.Fprintln(w, "Scans now use this bundle. Use --no-cached-rules to fall back to the built-in packs, or 'airom clean' to remove it.")
			return nil
		},
	}
	cmd.Flags().String("rules-source", "", "base URL to fetch the bundle from (default: the airom-rules release channel)")
	cmd.Flags().Bool("insecure-skip-signature", false, "skip ed25519 signature verification (NOT recommended; the checksum check still runs)")
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
		Short: "Validate a rule pack (or a model lifecycle catalog) against its full contract",
		Args:  exactArgs(1, "exactly one <file>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The signed bundle carries both rule packs and lifecycle catalogs,
			// so one lint command serves both — a maintainer should not have to
			// know which validator a file needs before checking it.
			if res, err := app.LintEOLCatalog(args[0]); err != nil {
				return &app.UsageError{Err: err}
			} else if res != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: OK (model lifecycle catalog: %s, %d model(s))\n",
					args[0], res.Provider, res.Models)
				return nil
			}
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
		Args:  exactArgs(1, "exactly one <file>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			// A publishing pipeline runs lint AND test over every YAML in the
			// bundle. A lifecycle catalog has no fixtures to run, so say that
			// plainly and succeed rather than failing with a rule-pack parse
			// error on a file that is not a rule pack.
			if res, err := app.LintEOLCatalog(args[0]); err != nil {
				return &app.UsageError{Err: err}
			} else if res != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: model lifecycle catalog (%s, %d model(s)) — validated by 'rules lint'; no fixtures to run\n",
					args[0], res.Provider, res.Models)
				return nil
			}
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
