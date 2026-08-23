package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/bench"
)

// newBenchCmd wires `airom bench` (docs/benchmark.md): scan a labeled corpus,
// report the metric set, and optionally gate against a baseline.
func newBenchCmd(info BuildInfo) *cobra.Command {
	var jsonOut, baseline string
	cmd := &cobra.Command{
		Use:   "bench <corpus-dir>",
		Short: "run the detection benchmark against a labeled corpus",
		Long: `Scan every entry of a labeled corpus (airomhq/airom-bench layout), grade
the results against the truth files, and print the metric report. Scans run
offline with the overlays off: the benchmark measures detection, and a number
that moves when OSV.dev does is not measuring the scanner.

With --baseline, the run is additionally compared against a previous bench
JSON under the gate policy of docs/benchmark.md §5, and the command exits
nonzero on a regression.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := bench.LoadCorpus(args[0])
			if err != nil {
				return err
			}
			results, tool, err := bench.Run(cmd.Context(), entries)
			if err != nil {
				return err
			}
			report := bench.Aggregate(info.Version, tool.RulesVersion, tool.RulesHash, results)

			fmt.Fprint(cmd.OutOrStdout(), report.Markdown())
			if jsonOut != "" {
				b, err := report.JSON()
				if err != nil {
					return err
				}
				if err := os.WriteFile(jsonOut, b, 0o644); err != nil { // #nosec G306 -- a report, not a secret
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "\nbench: wrote %s\n", jsonOut)
			}

			if baseline == "" {
				return nil
			}
			base, err := bench.LoadBaseline(baseline)
			if err != nil {
				return err
			}
			failures, remarks := bench.Compare(base, report)
			for _, r := range remarks {
				fmt.Fprintf(cmd.ErrOrStderr(), "bench: %s\n", r)
			}
			if len(failures) > 0 {
				for _, f := range failures {
					fmt.Fprintf(cmd.ErrOrStderr(), "bench: FAIL %s\n", f)
				}
				return fmt.Errorf("benchmark gate: %d regression(s) against %s", len(failures), baseline)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "bench: gate passed against %s\n", baseline)
			return nil
		},
	}
	cmd.Flags().StringVar(&jsonOut, "json", "", "also write the full metric report to this path")
	cmd.Flags().StringVar(&baseline, "baseline", "", "compare against a previous bench JSON and gate on regressions")
	return cmd
}
