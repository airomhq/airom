package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/transpiler"
)

func newTranspileCmd() *cobra.Command {
	var fromFormat string
	var toFormat string
	var outFile string

	cmd := &cobra.Command{
		Use:     "transpile <source-file>",
		GroupID: groupInspect,
		Short:   "Lossless bidirectional cross-format transpiler (CycloneDX, SPDX 3.0, OpenVEX)",
		Long: `Transpile software and AI Bill of Materials manifests between CycloneDX 1.6/1.7,
SPDX 3.0.1 AI Profile graphs, native AIROM JSON, and OpenVEX statements without loss
of model parameters, licensing metadata, or component evidence trails.`,
		Args: exactArgs(1, "exactly one <source-file>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcPath := args[0]
			data, err := os.ReadFile(srcPath)
			if err != nil {
				return fmt.Errorf("read source manifest %s: %w", srcPath, err)
			}

			srcFmt := transpiler.FormatCycloneDX
			if fromFormat == "spdx3" || fromFormat == "spdx" {
				srcFmt = transpiler.FormatSPDX3
			} else if fromFormat == "json" {
				srcFmt = transpiler.FormatNativeJSON
			}

			dstFmt := transpiler.FormatSPDX3
			if toFormat == "cyclonedx" || toFormat == "cdx" {
				dstFmt = transpiler.FormatCycloneDX
			} else if toFormat == "vex" || toFormat == "openvex" {
				dstFmt = transpiler.FormatOpenVEX
			}

			engine := transpiler.NewEngine()
			res, err := engine.Transpile(transpiler.TranspileRequest{
				SourceFormat: srcFmt,
				TargetFormat: dstFmt,
				Payload:      data,
			})
			if err != nil {
				return fmt.Errorf("transpilation error: %w", err)
			}

			if outFile != "" {
				if err := os.WriteFile(outFile, res.OutputPayload, 0o644); err != nil {
					return fmt.Errorf("write output manifest: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✅ Transpiled %s -> %s: %s (%d components, %d bytes)\n", srcFmt, dstFmt, outFile, res.ComponentsRead, len(res.OutputPayload))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), string(res.OutputPayload))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&fromFormat, "from", "cyclonedx", "source manifest format (cyclonedx, spdx3, json)")
	cmd.Flags().StringVar(&toFormat, "to", "spdx3", "target manifest format (spdx3, cyclonedx, openvex)")
	cmd.Flags().StringVarP(&outFile, "out", "O", "", "output manifest file path (default: stdout)")

	return cmd
}
