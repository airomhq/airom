package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/filing"
)

func newFileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "file",
		GroupID: groupCompliance,
		Short:   "Generate, verify, and submit statutory regulatory filings and track renewal calendars",
		Long: `Automated State Portal Filing Agent and Calendar Renewal Tracker for multi-jurisdiction AI regulations.
Supports Colorado AG SB 24-205, California CPPA AB 2013, NYC DCWP Local Law 144, EU AI Act Article 50,
Illinois BIPA, Texas TRAIGA, and Virginia VCDPA.`,
	}

	cmd.AddCommand(newFileGenerateCmd())
	cmd.AddCommand(newFileVerifyCmd())
	cmd.AddCommand(newFileCalendarCmd())
	cmd.AddCommand(newFileSubmitCmd())

	return cmd
}

func newFileGenerateCmd() *cobra.Command {
	var (
		state       string
		outDir      string
		orgID       string
		orgName     string
		repoID      string
		signerName  string
		signerTitle string
		signerEmail string
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Compile and cryptographically seal a state regulatory filing package",
		RunE: func(cmd *cobra.Command, _ []string) error {
			builder := filing.NewPackageBuilder()
			jurisdiction := parseJurisdiction(state)

			if outDir == "" {
				outDir = fmt.Sprintf("./filings/%s", strings.ToLower(string(jurisdiction)))
			}
			if signerName == "" {
				signerName = "Authorized Compliance Officer"
			}
			if signerEmail == "" {
				signerEmail = "compliance@enterprise.internal"
			}
			if signerTitle == "" {
				signerTitle = "Chief Compliance Officer"
			}

			opts := filing.BuildPackageOptions{
				Jurisdiction:     jurisdiction,
				OrganizationID:   orgID,
				OrganizationName: orgName,
				RepositoryID:     repoID,
				SignerName:       signerName,
				SignerTitle:      signerTitle,
				SignerEmail:      signerEmail,
				AuditDate:        time.Now().UTC(),
				ModelIDs:         []string{"gpt-4o", "claude-3-5-sonnet"},
				ControlsMetCount: 18,
				ControlsGapCount: 0,
			}

			manifest, err := builder.BuildPackage(opts)
			if err != nil {
				return fmt.Errorf("failed to assemble filing package: %w", err)
			}

			if err := builder.ExportToDirectory(manifest, outDir); err != nil {
				return fmt.Errorf("failed to export filing directory: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Generated and Sealed Statutory Filing Package for %s\n", manifest.Jurisdiction)
			fmt.Fprintf(cmd.OutOrStdout(), "  Package ID:        %s\n", manifest.PackageID)
			fmt.Fprintf(cmd.OutOrStdout(), "  Statutory Ref:     %s\n", manifest.StatutoryReference)
			fmt.Fprintf(cmd.OutOrStdout(), "  Package Checksum:  %s\n", manifest.PackageChecksum)
			fmt.Fprintf(cmd.OutOrStdout(), "  Signer:            %s <%s> (%s)\n", manifest.Signer.OfficerName, manifest.Signer.OfficerEmail, manifest.Signer.OfficerTitle)
			fmt.Fprintf(cmd.OutOrStdout(), "  Destination:       %s\n", outDir)
			fmt.Fprintf(cmd.OutOrStdout(), "  Artifacts Included (%d):\n", len(manifest.Artifacts))
			for _, art := range manifest.Artifacts {
				fmt.Fprintf(cmd.OutOrStdout(), "    - %-48s (%d bytes, SHA: %s)\n", art.RelativePath, art.SizeBytes, art.SHA256[:16]+"...")
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&state, "state", "s", "colorado", "Target state jurisdiction (colorado, california, nyc, eu, illinois, texas, virginia)")
	flags.StringVarP(&outDir, "out", "O", "", "Destination directory for filing package")
	flags.StringVar(&orgID, "org", "org_enterprise", "Enterprise organization ID")
	flags.StringVar(&orgName, "org-name", "Enterprise Corporation", "Legal organization entity name")
	flags.StringVar(&repoID, "repo", "main-service", "Target codebase repository ID")
	flags.StringVar(&signerName, "signer", "Chief Compliance Officer", "Attesting officer name")
	flags.StringVar(&signerTitle, "title", "VP of AI Governance", "Attesting officer corporate title")
	flags.StringVar(&signerEmail, "email", "governance@enterprise.internal", "Attesting officer email")

	return cmd
}

func newFileVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <package_dir>",
		Short: "Cryptographically verify a generated statutory filing package against tamper drift",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pkgDir := args[0]
			agent := filing.NewFilingAgent(nil)

			manifest, err := agent.VerifyPackage(pkgDir)
			if err != nil {
				return fmt.Errorf("❌ Filing Package Verification FAILED: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Filing Package Verification SUCCESSFUL\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  Package ID:       %s\n", manifest.PackageID)
			fmt.Fprintf(cmd.OutOrStdout(), "  Jurisdiction:     %s\n", manifest.Jurisdiction)
			fmt.Fprintf(cmd.OutOrStdout(), "  Statutory Ref:    %s\n", manifest.StatutoryReference)
			fmt.Fprintf(cmd.OutOrStdout(), "  Package Checksum: %s\n", manifest.PackageChecksum)
			fmt.Fprintf(cmd.OutOrStdout(), "  Attestation Sig:  %s\n", manifest.Signer.SignatureHash)
			fmt.Fprintf(cmd.OutOrStdout(), "  Artifacts (%d):   All cryptographic hashes verified on disk with zero bit-drift.\n", len(manifest.Artifacts))

			return nil
		},
	}
}

func newFileCalendarCmd() *cobra.Command {
	var (
		orgID  string
		asJSON bool
	)

	cmd := &cobra.Command{
		Use:   "calendar",
		Short: "Display multi-jurisdiction compliance renewal schedule and statutory deadlines",
		RunE: func(cmd *cobra.Command, _ []string) error {
			engine := filing.NewRenewalEngine()
			history := make(filing.FilingHistoryMap)
			mods := make(filing.SubstantialModMap)

			calendar := engine.ComputeCalendar(orgID, history, mods, time.Now().UTC())

			if asJSON {
				data, err := json.MarshalIndent(calendar, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			fmt.Fprint(cmd.OutOrStdout(), engine.RenderCalendarTable(calendar))
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&orgID, "org", "default-org", "Enterprise organization ID")
	flags.BoolVar(&asJSON, "json", false, "Output renewal schedule as JSON")

	return cmd
}

func newFileSubmitCmd() *cobra.Command {
	var (
		pkgDir   string
		endpoint string
	)

	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Verify and transmit a statutory filing package to a state portal",
		RunE: func(cmd *cobra.Command, _ []string) error {
			agent := filing.NewFilingAgent(nil)
			manifest, err := agent.VerifyPackage(pkgDir)
			if err != nil {
				return fmt.Errorf("package pre-flight verification failed: %w", err)
			}

			receipt, err := agent.SubmitPackage(context.Background(), manifest, endpoint)
			if err != nil {
				return fmt.Errorf("filing submission failed: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Statutory Filing Successfully Transmitted & Acknowledged\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  Receipt ID:   %s\n", receipt.ReceiptID)
			fmt.Fprintf(cmd.OutOrStdout(), "  Jurisdiction: %s\n", receipt.Jurisdiction)
			fmt.Fprintf(cmd.OutOrStdout(), "  Status:       %s\n", receipt.Status)
			fmt.Fprintf(cmd.OutOrStdout(), "  Ack Token:    %s\n", receipt.AcknowledgmentToken)
			fmt.Fprintf(cmd.OutOrStdout(), "  Message:      %s\n", receipt.Message)

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&pkgDir, "pkg", "p", "./filings/co-ag", "Path to package directory containing filing_manifest.json")
	flags.StringVarP(&endpoint, "endpoint", "e", "", "State portal endpoint URL (optional)")

	_ = cmd.MarkFlagRequired("pkg")
	return cmd
}

func parseJurisdiction(s string) filing.Jurisdiction {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "california", "ca", "ab2013", "ca-cppa":
		return filing.JurisdictionCalifornia
	case "nyc", "ll144", "dcwp", "nyc-dcwp":
		return filing.JurisdictionNYC
	case "eu", "eu-ai-act", "eu-ai-office":
		return filing.JurisdictionEU
	case "illinois", "il", "bipa", "il-bipa":
		return filing.JurisdictionIllinois
	case "texas", "tx", "traiga", "tx-traiga":
		return filing.JurisdictionTexas
	case "virginia", "va", "vcdpa", "va-vcdpa":
		return filing.JurisdictionVirginia
	default:
		return filing.JurisdictionColorado
	}
}
