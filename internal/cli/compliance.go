package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/app"
	"github.com/airomhq/airom/internal/compliance"
	"github.com/airomhq/airom/internal/source"
)

func newComplianceCmd() *cobra.Command {
	var frameworkName string
	var failOnGap bool

	cmd := &cobra.Command{
		Use:     "compliance [target]",
		GroupID: groupInspect,
		Short:   "Evaluate statutory AI compliance against state and international governance frameworks",
		Long: `Map an AI Bill of Materials onto statutory compliance frameworks (Colorado AI Act,
EU AI Act, CA AB 2013, NYC LL144, Illinois BIPA, Texas TRAIGA, Virginia VCDPA, NIST AI RMF, ISO 42001).

Always a mapping, never a certification.`,
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

			// If framework not specified or set to all, evaluate all frameworks
			var frameworks []string
			if frameworkName == "" || frameworkName == "all" {
				frameworks = compliance.IDs()
			} else {
				frameworks = strings.Split(frameworkName, ",")
			}

			flags := cmd.Flags()
			_ = flags.Set("output", "compliance")
			for _, fw := range frameworks {
				_ = flags.Set("compliance", fw)
			}

			if failOnGap {
				_ = flags.Set("fail-on", "compliance:gap")
			}

			cfg, err := buildConfig(flags, wd, src, detectedTarget)
			if err != nil {
				return err
			}

			return runScan(cmd.Context(), cfg)
		},
	}

	cmd.Flags().StringVarP(&frameworkName, "framework", "f", "colorado-ai-act", fmt.Sprintf("governance framework to evaluate; valid: all, %s", strings.Join(compliance.IDs(), ", ")))
	cmd.Flags().BoolVar(&failOnGap, "fail-on-gap", false, "exit with status 1 if any statutory compliance gap is detected")

	return cmd
}
