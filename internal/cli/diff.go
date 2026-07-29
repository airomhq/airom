package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/app"
	"github.com/airomhq/airom/internal/diff"
	"github.com/airomhq/airom/pkg/airom"
)

func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "diff <old-aibom.json> <new-aibom.json>",
		GroupID: groupInspect,
		Short:   "Compare two native AIBOM documents: what AI was added, removed, or changed",
		Long: `Diff two native AIBOM JSON documents (airom scan <target> -o json=<file>) and
report the semantic delta: components added, removed, and changed, keyed by
the stable component ID. Version is not part of identity, so a version bump
reads as a field change on one component, never as a remove+add pair.
Evidence churn (occurrence counts, detector sets) is not compared.

Output is one format to stdout: table (default), markdown (ready to post as
a PR comment), or json — selected with --format. The scan root and
test-scoped components are excluded by default (--include-tests to count
them).

The gate flags work like scan's, evaluated over the added and changed
components only: --fail-on names the AI delta you refuse to merge, and
--exit-code N alone fails on any added or changed component. Removals never
trip the gate. compliance: terms are not applicable to a diff.`,
		Example: example(
			[2]string{"What AI changed between two scans?", "airom diff old.json new.json"},
			[2]string{"PR comment: scan base and head, then diff", "airom diff base.json head.json --format markdown"},
			[2]string{"Fail CI when a PR introduces a new hosted model", `airom diff base.json head.json --fail-on "hosted-llm|local-model-file"`},
			[2]string{"Fail CI on any AI change at all", "airom diff base.json head.json --exit-code 1"},
		),
		Args: exactArgs(2, "exactly two native AIBOM files: <old.json> <new.json>"),
		RunE: runDiff,
	}
	return cmd
}

func runDiff(cmd *cobra.Command, args []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("determine working directory: %w", err)
	}
	l, err := loadLayers(cmd.Flags(), wd)
	if err != nil {
		return err
	}

	includeTests, err := boolKey(l.k, "include-tests")
	if err != nil {
		return &app.UsageError{Err: err}
	}
	policy, exitCode, err := resolvePolicy(l.k)
	if err != nil {
		return &app.UsageError{Err: err}
	}
	if policy != nil && policy.ReferencesCompliance() {
		return &app.UsageError{Err: fmt.Errorf("--fail-on %q: compliance terms gate a scan's framework mapping and are not applicable to a diff", policy)}
	}
	format, err := resolveDiffFormat(cmd)
	if err != nil {
		return err
	}

	oldInv, err := diff.Load(args[0])
	if err != nil {
		return err
	}
	newInv, err := diff.Load(args[1])
	if err != nil {
		return err
	}

	res := diff.Compute(oldInv, newInv, includeTests)
	res.OldPath, res.NewPath = args[0], args[1]

	// Emit first, gate last — the report must be complete before the exit
	// code says anything about it (same order as app.Run).
	if err := diff.Render(cmd.OutOrStdout(), format, res); err != nil {
		return err
	}
	if policy != nil {
		// The gated set is pre-filtered by --include-tests above, so the
		// policy itself must not filter again.
		gated := &airom.Inventory{Components: res.GateComponents()}
		if policy.Matches(gated, true) {
			return &app.PolicyExit{Code: exitCode}
		}
	}
	return nil
}

// resolveDiffFormat picks the diff output format from the global --format
// flag. Only the flag itself is consulted: a `format:` in .airom.yaml or
// AIROM_FORMAT configures scan output (cyclonedx, sarif, …) and must not
// break diff, whose format set is its own. -o/--output is scan-only and is
// rejected explicitly rather than silently ignored.
func resolveDiffFormat(cmd *cobra.Command) (string, error) {
	if cmd.Flags().Changed("output") {
		return "", &app.UsageError{Err: fmt.Errorf("diff renders one format to stdout; use --format %s, not -o/--output",
			strings.Join(diff.Formats(), "|"))}
	}
	if !cmd.Flags().Changed("format") {
		return diff.Formats()[0], nil
	}
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return "", err
	}
	format = strings.TrimSpace(format)
	for _, f := range diff.Formats() {
		if format == f {
			return format, nil
		}
	}
	return "", &app.UsageError{Err: fmt.Errorf("unknown diff format %q (formats: %s)", format, strings.Join(diff.Formats(), ", "))}
}
