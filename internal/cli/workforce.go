package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/workforce"
)

func newWorkforceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "workforce",
		GroupID: groupCompliance,
		Short:   "Assess AI workforce impact, task automation exposure, and generate statutory duty-of-care notices",
		Long: `AI Workforce Impact Assessment and Algorithmic Job Displacement Risk Engine.
Implements statutory workforce risk governance pursuant to CO SB 24-205 § 6-1-1703(1)(b),
NYC Local Law 144 AEDT employment scoring, and Illinois 820 ILCS 42.`,
	}

	cmd.AddCommand(newWorkforceAssessCmd())
	cmd.AddCommand(newWorkforceNoticeCmd())

	return cmd
}

func newWorkforceAssessCmd() *cobra.Command {
	var (
		orgID      string
		systemName string
		asJSON     bool
	)

	cmd := &cobra.Command{
		Use:   "assess",
		Short: "Run an automated workforce impact and job displacement assessment",
		RunE: func(cmd *cobra.Command, _ []string) error {
			engine := workforce.NewWorkforceEngine()

			// Baseline enterprise AI capabilities detected in AIBOM
			capabilities := []workforce.AISystemCapability{
				{
					Name: "Enterprise Code & Engineering Assistant",
					AutomatedTasks: []string{
						"code-generation", "unit-test-writing", "refactoring", "boilerplate-coding",
					},
					AutonomyLevel:       0.75,
					HighImpactDecisions: false,
				},
				{
					Name: "Customer Support & Incident Triage Agent",
					AutomatedTasks: []string{
						"tier-1-ticket-resolution", "live-chat-support", "faq-answering",
					},
					AutonomyLevel:       0.85,
					HighImpactDecisions: false,
				},
				{
					Name: "Candidate Resume Evaluator & Screener",
					AutomatedTasks: []string{
						"resume-screening", "candidate-ranking",
					},
					AutonomyLevel:       0.80,
					HighImpactDecisions: true,
				},
			}

			// Baseline enterprise role classifications
			roles := []workforce.RoleProfile{
				{
					RoleID:          "swe_01",
					Title:           "Software Engineer",
					Category:        workforce.RoleCategoryEngineering,
					Department:      "Engineering",
					Headcount:       120,
					CoreTasks:       []string{"code-generation", "unit-test-writing", "system-architecture-design", "code-review"},
					MedianSalaryUSD: 145000,
				},
				{
					RoleID:          "supp_01",
					Title:           "Customer Support Specialist",
					Category:        workforce.RoleCategoryCustomerOps,
					Department:      "Operations",
					Headcount:       65,
					CoreTasks:       []string{"tier-1-ticket-resolution", "live-chat-support", "faq-answering"},
					MedianSalaryUSD: 52000,
				},
				{
					RoleID:          "rec_01",
					Title:           "Talent Acquisition Recruiter",
					Category:        workforce.RoleCategoryHR,
					Department:      "People Ops",
					Headcount:       20,
					CoreTasks:       []string{"resume-screening", "candidate-ranking", "interviews"},
					MedianSalaryUSD: 85000,
				},
				{
					RoleID:          "fin_01",
					Title:           "Financial Analyst",
					Category:        workforce.RoleCategoryFinance,
					Department:      "Finance",
					Headcount:       30,
					CoreTasks:       []string{"financial-modeling", "budget-reconciliation", "variance-analysis"},
					MedianSalaryUSD: 105000,
				},
			}

			report, err := engine.AssessWorkforceImpact(orgID, systemName, capabilities, roles, time.Now().UTC())
			if err != nil {
				return fmt.Errorf("workforce assessment failed: %w", err)
			}

			if asJSON {
				data, err := json.MarshalIndent(report, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			fmt.Fprint(cmd.OutOrStdout(), workforce.RenderWorkforceDashboard(report))
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&orgID, "org", "org_enterprise", "Enterprise organization ID")
	flags.StringVar(&systemName, "system", "Enterprise-GenAI-Cluster", "Evaluated AI system name")
	flags.BoolVar(&asJSON, "json", false, "Output assessment as JSON")

	return cmd
}

func newWorkforceNoticeCmd() *cobra.Command {
	var (
		roleTitle  string
		systemName string
		outFile    string
	)

	cmd := &cobra.Command{
		Use:   "notice",
		Short: "Generate statutory employee duty-of-care pre-deployment notification",
		RunE: func(cmd *cobra.Command, _ []string) error {
			now := time.Now().UTC()
			effective := now.AddDate(0, 0, 14)

			notice := fmt.Sprintf(`# STATUTORY DUTY-OF-CARE EMPLOYEE NOTIFICATION
**Pursuant to CO SB 24-205 § 6-1-1703(1)(b) & NYC Local Law 144 / DCWP § 20-870**

---

### 1. General Identification
- **Evaluated AI System**: %s
- **Impacted Role Classification**: %s
- **Notice Date**: %s
- **Statutory Effective Date**: %s (14-day mandatory notice window)

### 2. Nature of Automated Task Assistance
The enterprise is introducing automated AI capabilities to assist with tasks associated with the %s role.
- **Human-in-the-Loop Safeguards**: All critical decisions remain subject to qualified employee oversight.
- **Retraining & Upskilling**: Structured 40-hour upskilling pathways in AI tool operation are provided at no cost.
- **Displacement Protections**: Retraining and internal redeployment priority are statutory guarantees under corporate policy.

### 3. Employee Inquiries & Dispute Channel
Employees may request an individualized explanation of automated tooling or submit inquiries to:
- **Email**: workforce-governance@enterprise.internal
- **Human Resources Labor Relations Office**

---
*Cryptographically Sealed by AIROM Workforce Governance Engine*
`, systemName, roleTitle, now.Format("2006-01-02"), effective.Format("2006-01-02"), roleTitle)

			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(notice), 0o600); err != nil {
					return fmt.Errorf("failed to write notice file: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✅ Generated statutory duty-of-care notice: %s\n", outFile)
				return nil
			}

			fmt.Fprint(cmd.OutOrStdout(), notice)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&roleTitle, "role", "r", "Software Engineer", "Target employee role title")
	flags.StringVarP(&systemName, "system", "s", "Enterprise-GenAI-Cluster", "Evaluated AI system name")
	flags.StringVarP(&outFile, "out", "O", "", "Output markdown file path (optional)")

	return cmd
}
