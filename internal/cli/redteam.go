package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/redteam"
)

func newRedTeamCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "redteam",
		GroupID: groupCompliance,
		Short:   "Execute automated adversarial penetration probes and prompt injection audits",
		Long: `Automated Penetration & Red Team Security Prober.
Tests AI model deployments and runtime gateways against OWASP LLM Top 10 vectors,
including direct/indirect prompt injection, system prompt extraction, and unbounded tool hijacking.`,
	}

	cmd.AddCommand(newRedTeamProbeCmd())

	return cmd
}

func newRedTeamProbeCmd() *cobra.Command {
	var (
		targetURL string
		modelName string
		asJSON    bool
	)

	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Execute automated penetration probes against an AI model endpoint or gateway",
		RunE: func(cmd *cobra.Command, _ []string) error {
			engine := redteam.NewRedTeamEngine()

			assessment, err := engine.ExecuteAssessment(context.Background(), targetURL, modelName, nil)
			if err != nil {
				return fmt.Errorf("red team probe failed: %w", err)
			}

			if asJSON {
				data, err := json.MarshalIndent(assessment, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			fmt.Fprint(cmd.OutOrStdout(), redteam.RenderRedTeamDashboard(assessment))
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&targetURL, "target", "t", "https://api.airom.internal/v1/gateway", "Target AI model or gateway URL")
	flags.StringVarP(&modelName, "model", "m", "claude-3-5-sonnet", "Target AI model identifier")
	flags.BoolVar(&asJSON, "json", false, "Output red team assessment as JSON")

	return cmd
}
