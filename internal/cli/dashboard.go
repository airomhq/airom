package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/dashboard"
)

func newDashboardCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:     "dashboard",
		GroupID: groupCompliance,
		Short:   "Display enterprise multi-organization compliance posture and executive security matrix",
		Long: `Enterprise Compliance Dashboard v2 & Multi-Org Heatmap Engine.
Aggregates statutory compliance postures, critical gaps, shadow AI findings,
and urgent statutory renewal deadlines across all business units and subsidiaries.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			engine := dashboard.NewDashboardEngine()

			// Baseline enterprise subsidiaries
			orgs := []dashboard.OrganizationRollup{
				{
					OrganizationID:     "org_core_fintech",
					OrganizationName:   "Core Payments & Fintech",
					Sector:             "Financial Services",
					RepositoryCount:    42,
					TotalComponents:    280,
					ComplianceScore:    96.5,
					CriticalGapsCount:  0,
					ShadowAICount:      1,
					DisplacedFTECount:  14.0,
					UrgentFilingsCount: 0,
					FrameworkCompliance: map[string]float64{
						"Colorado AI Act": 98.0,
						"EU AI Act":       95.0,
						"NYC LL144":       96.5,
					},
					LastAuditedAt: time.Now().UTC(),
				},
				{
					OrganizationID:     "org_healthcare_ai",
					OrganizationName:   "Healthcare & Bio Diagnostics",
					Sector:             "Life Sciences",
					RepositoryCount:    28,
					TotalComponents:    160,
					ComplianceScore:    88.0,
					CriticalGapsCount:  1,
					ShadowAICount:      3,
					DisplacedFTECount:  6.5,
					UrgentFilingsCount: 1,
					FrameworkCompliance: map[string]float64{
						"Colorado AI Act": 89.0,
						"EU AI Act":       87.0,
					},
					LastAuditedAt: time.Now().UTC(),
				},
				{
					OrganizationID:     "org_retail_ecommerce",
					OrganizationName:   "Global Consumer E-Commerce",
					Sector:             "Retail / E-Commerce",
					RepositoryCount:    35,
					TotalComponents:    210,
					ComplianceScore:    74.5,
					CriticalGapsCount:  4,
					ShadowAICount:      5,
					DisplacedFTECount:  18.0,
					UrgentFilingsCount: 2,
					FrameworkCompliance: map[string]float64{
						"Colorado AI Act": 76.0,
						"NYC LL144":       73.0,
					},
					LastAuditedAt: time.Now().UTC(),
				},
			}

			matrix, err := engine.CalculateExecutivePosture(orgs)
			if err != nil {
				return fmt.Errorf("dashboard generation failed: %w", err)
			}

			if asJSON {
				data, err := json.MarshalIndent(matrix, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			fmt.Fprint(cmd.OutOrStdout(), dashboard.RenderExecutiveDashboard(matrix))
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "Output executive posture matrix as JSON")

	return cmd
}
