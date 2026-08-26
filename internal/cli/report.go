package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/app"
	"github.com/airomhq/airom/internal/compliance"
	"github.com/airomhq/airom/internal/source"
	"github.com/airomhq/airom/services/saas/pdf"
)

func newReportCmd() *cobra.Command {
	var frameworkName string
	var reportFormat string
	var outFile string
	var orgName string

	cmd := &cobra.Command{
		Use:     "report [target]",
		GroupID: groupInspect,
		Short:   "Generate publication-grade compliance dossiers in PDF, HTML, or Markdown",
		Long: `Generate executive-ready, publication-grade AI compliance reports.
Supports ISO 32000-1 vector PDF generation (pure-Go, zero external binaries),
WCAG 2.1 AA accessible HTML, and statutory Markdown dossiers.`,
		Args: maxArgs(1, "at most one [target]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}

			kind, detectedTarget, err := source.DetectTarget(target)
			if err != nil {
				return &app.UsageError{Err: err}
			}
			var src app.SourceKind
			switch kind {
			case source.TargetDir:
				src = app.SourceFS
			case source.TargetRepo:
				src = app.SourceRepo
			case source.TargetImage:
				src = app.SourceImage
			}

			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("determine working directory: %w", err)
			}

			if orgName == "" {
				orgName = "Enterprise AI Systems"
			}

			flags := cmd.Flags()
			cfg, err := buildConfig(flags, wd, src, detectedTarget)
			if err != nil {
				return err
			}

			inv, err := app.Scan(cmd.Context(), cfg)
			if err != nil {
				return err
			}

			// Evaluate compliance for report
			var fwList []string
			if frameworkName == "" || frameworkName == "all" {
				fwList = []string{"colorado-ai-act"}
			} else {
				fwList = []string{frameworkName}
			}

			results, err := compliance.Evaluate(inv, fwList, cfg.IncludeTests)
			if err != nil {
				return err
			}

			metCount := 0
			gapCount := 0
			if len(results) > 0 {
				for _, c := range results[0].Controls {
					if c.State == "met" {
						metCount++
					} else if c.State == "gap" {
						gapCount++
					}
				}
			}

			switch reportFormat {
			case "pdf":
				pdfGen := pdf.NewGenerator()
				repoName := filepath.Base(detectedTarget)
				if repoName == "." || repoName == "" {
					repoName = filepath.Base(wd)
				}

				docSpec := pdf.DocumentSpec{
					Title:            fmt.Sprintf("AI Governance & Statutory Compliance Dossier (%s)", frameworkName),
					OrganizationName: orgName,
					RepositoryName:   repoName,
					FrameworkName:    frameworkName,
					ExecutiveSummary: fmt.Sprintf("AIROM automated static scan completed over %d components with %d controls met and %d statutory gaps.", len(inv.Components), metCount, gapCount),
					TotalComponents:  len(inv.Components),
					ControlsMet:      metCount,
					GapsIdentified:   gapCount,
					GeneratedAt:      time.Now().UTC(),
				}

				dossier := pdfGen.GeneratePDF(docSpec)
				if outFile == "" {
					outFile = fmt.Sprintf("airom-compliance-report-%s.pdf", frameworkName)
				}
				if err := os.WriteFile(outFile, dossier.PDFBytes, 0o644); err != nil {
					return fmt.Errorf("write pdf file: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✅ Generated Executive Vector PDF Report: %s (%d bytes)\n", outFile, len(dossier.PDFBytes))
				return nil

			default:
				// Default markdown/compliance output
				_ = flags.Set("output", "compliance")
				_ = flags.Set("compliance", frameworkName)
				return runScan(cmd.Context(), cfg)
			}
		},
	}

	cmd.Flags().StringVarP(&frameworkName, "framework", "f", "colorado-ai-act", "governance framework for the report (colorado-ai-act, eu-ai-act, ca-ab2013, nist-ai-rmf)")
	cmd.Flags().StringVarP(&reportFormat, "type", "t", "pdf", "report output type (pdf, markdown)")
	cmd.Flags().StringVarP(&outFile, "out", "O", "", "output file path (default: airom-compliance-report-<framework>.pdf)")
	cmd.Flags().StringVar(&orgName, "org", "Enterprise AI Systems", "organization name to display in the executive report")

	return cmd
}
