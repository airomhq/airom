package cli

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/cockpit"
)

func newCockpitCmd() *cobra.Command {
	var port int
	var org string
	var noBlock bool

	cmd := &cobra.Command{
		Use:     "cockpit",
		GroupID: groupInspect,
		Short:   "Start the interactive embedded enterprise AI governance cockpit web server",
		Long: `Start a lightweight, pure-Go zero-dependency web cockpit delivering an interactive
dark-mode enterprise AI governance dashboard with real-time SSE statutory updates,
AIBOM asset graphs, and regulatory scorecards.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if port == 0 {
				port = 8088
			}
			if org == "" {
				org = "Enterprise AI Systems"
			}

			server := cockpit.NewServer(cockpit.CockpitConfig{
				Port:         port,
				Organization: org,
				EnableSSE:    true,
			})

			addr := fmt.Sprintf(":%d", port)
			fmt.Fprintf(cmd.OutOrStdout(), "🚀 AIROM Enterprise Governance Cockpit listening on http://localhost:%d (Org: %s)\n", port, org)
			fmt.Fprintln(cmd.OutOrStdout(), "   Press Ctrl+C to stop.")

			if noBlock {
				return nil
			}

			return http.ListenAndServe(addr, server.Routes())
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 8088, "HTTP port for web cockpit")
	cmd.Flags().StringVar(&org, "org", "Enterprise AI Systems", "Organization name for the dashboard")
	cmd.Flags().BoolVar(&noBlock, "no-block", false, "start without blocking (testing)")

	return cmd
}
