package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Roro1727/airom/internal/app"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// newDetectorsCmd is the explainability view (§6.2, docs/cli.md):
// capability-as-data makes the scanner self-documenting.
func newDetectorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detectors",
		Short: "Inspect the detector catalog (the self-documenting capability view)",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List detectors with their selection status (honors --select and --rules)",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				infos, err := detectorInfos(cmd)
				if err != nil {
					return err
				}
				w := cmd.OutOrStdout()
				if len(infos) == 0 {
					fmt.Fprintln(w, "no detectors registered (built-ins land in Phase 6; rule packs via --rules)")
					return nil
				}
				fmt.Fprintf(w, "%-24s %-8s %-8s %-10s %s\n", "ID", "VERSION", "PHASE", "SELECTED", "SELECTS")
				for _, in := range infos {
					selected := in.SelectedBy
					if selected == "" {
						selected = "-"
					}
					fmt.Fprintf(w, "%-24s %-8d %-8s %-10s %s\n",
						in.ID, in.Version, in.Phase, selected, selectorSummary(in.Selector, in.RuleCount))
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "explain <id>",
			Short: "Print one detector's full selector, needs, and rule count",
			Args:  exactArgs("exactly one <id>"),
			RunE: func(cmd *cobra.Command, args []string) error {
				infos, err := detectorInfos(cmd)
				if err != nil {
					return err
				}
				for _, in := range infos {
					if in.ID != args[0] {
						continue
					}
					w := cmd.OutOrStdout()
					fmt.Fprintf(w, "id:        %s\n", in.ID)
					fmt.Fprintf(w, "version:   %d\n", in.Version)
					fmt.Fprintf(w, "phase:     %s\n", in.Phase)
					fmt.Fprintf(w, "selects:   %s\n", selectorSummary(in.Selector, in.RuleCount))
					fmt.Fprintf(w, "need:      %s\n", needName(in.Selector.Need))
					if in.SelectedBy != "" {
						fmt.Fprintf(w, "selected:  %s\n", in.SelectedBy)
					} else {
						fmt.Fprintf(w, "selected:  no (excluded by --select)\n")
					}
					return nil
				}
				return &app.UsageError{Err: fmt.Errorf("no detector %q (see 'airom detectors list')", args[0])}
			},
		},
	)
	return cmd
}

// detectorInfos builds the catalog view from the layered configuration.
func detectorInfos(cmd *cobra.Command) ([]app.DetectorInfo, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("determine working directory: %w", err)
	}
	cfg, err := buildConfig(cmd.Flags(), wd, app.SourceFS, ".")
	if err != nil {
		return nil, err
	}
	return app.Detectors(cfg)
}

func selectorSummary(sel detect.Selector, ruleCount int) string {
	var parts []string
	if len(sel.Basenames) > 0 {
		parts = append(parts, "base:"+strings.Join(sel.Basenames, "|"))
	}
	if len(sel.Extensions) > 0 {
		parts = append(parts, "ext:"+strings.Join(sel.Extensions, "|"))
	}
	if len(sel.PathGlobs) > 0 {
		parts = append(parts, "glob:"+strings.Join(sel.PathGlobs, "|"))
	}
	if len(sel.Languages) > 0 {
		langs := make([]string, len(sel.Languages))
		for i, l := range sel.Languages {
			langs[i] = string(l)
		}
		parts = append(parts, "lang:"+strings.Join(langs, "|"))
	}
	if len(sel.Magic) > 0 {
		parts = append(parts, fmt.Sprintf("magic:%d signature(s)", len(sel.Magic)))
	}
	if sel.MaxSize > 0 {
		parts = append(parts, fmt.Sprintf("max-size:%d", sel.MaxSize))
	}
	if ruleCount > 0 {
		parts = append(parts, fmt.Sprintf("rules:%d", ruleCount))
	}
	if len(parts) == 0 {
		return "every file"
	}
	return strings.Join(parts, " · ")
}

func needName(n detect.Need) string {
	switch n {
	case detect.NeedContent:
		return "content"
	case detect.NeedHeader:
		return "header"
	default:
		return "stat"
	}
}
