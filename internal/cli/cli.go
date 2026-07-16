// Package cli implements the airom command tree, configuration layering, and
// exit-code policy (ARCHITECTURE.md §12, docs/cli.md). Commands contain zero
// scan logic: they resolve configuration and hand a fully-built *app.Config
// to the composition root.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Roro1727/airom/internal/app"
	"github.com/Roro1727/airom/pkg/airom"
)

// BuildInfo carries the ldflags-stamped build metadata from cmd/airom.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// runScan is the seam between the CLI and the composition root; tests
// substitute it to capture the resolved Config without running a scan.
var runScan = app.Run

// Exit codes per the docs/cli.md contract. Scan success is always 0 —
// findings are not failures. The policy exit code (--exit-code, default 1
// when --fail-on is active) is returned by the engine path once it lands.
const (
	exitOK    = 0
	exitFatal = 2
)

// Execute runs the airom CLI and returns the process exit code.
func Execute(ctx context.Context, bi BuildInfo) int {
	app.Tool = airom.ToolInfo{Name: "airom", Version: bi.Version, Commit: bi.Commit}
	if err := checkPProfForm(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "airom: invalid configuration: %v\n", err)
		return exitFatal
	}
	root := newRootCmd(bi)
	if err := root.ExecuteContext(ctx); err != nil {
		var uerr *app.UsageError
		if errors.As(err, &uerr) {
			fmt.Fprintf(os.Stderr, "airom: invalid configuration: %v\n", uerr.Err)
		} else {
			fmt.Fprintf(os.Stderr, "airom: error: %v\n", err)
		}
		return exitFatal
	}
	return exitOK
}

func newRootCmd(bi BuildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:   "airom",
		Short: "AIROM — AI Bill of Materials scanner",
		Long: `AIROM discovers AI assets (models, embeddings, frameworks, vector databases,
prompts, datasets, generation parameters, serving infrastructure, RAG
pipelines) in filesystems, repositories, container images, and Kubernetes
workloads, and emits an evidence-first AIBOM.

Exit codes: 0 = scan completed (findings are NOT failures); use
--exit-code/--fail-on for opt-in CI gates; 2 = fatal error. See docs/cli.md.`,
		Version:       fmt.Sprintf("%s (commit %s, built %s)", bi.Version, bi.Commit, bi.Date),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return setupLogging(cmd)
		},
	}
	root.SetVersionTemplate("airom {{.Version}}\n")

	// Flag-parse errors keep a usage hint despite SilenceUsage — a typo'd
	// flag must never produce a single terse line with no way forward.
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return &app.UsageError{Err: fmt.Errorf("%v\nRun '%s --help' for usage", err, cmd.CommandPath())}
	})

	addGlobalFlags(root.PersistentFlags())

	root.AddCommand(
		newScanCmd(),
		newFSCmd(),
		newRepoCmd(),
		newImageCmd(),
		newK8sCmd(),
		newDetectorsCmd(),
		newRulesCmd(),
		newDevCmd(),
		newCleanCmd(),
		newVersionCmd(bi),
	)
	return root
}

// setupLogging configures the process-wide slog default from -v/-q,
// resolved through the same flags > env > file layering as every other
// global flag (AIROM_QUIET=true and `quiet: true` in .airom.yaml work).
// Default level is Info; -v enables Debug, -vv adds source locations,
// -q restricts to errors.
func setupLogging(cmd *cobra.Command) error {
	verbose, quiet := 0, false
	if cmd.Flags().Lookup("verbose") != nil { // commands carrying the persistent flags
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("determine working directory: %w", err)
		}
		l, err := loadLayers(cmd.Flags(), wd)
		if err != nil {
			return err
		}
		if verbose, err = intKey(l.k, "verbose"); err != nil {
			return &app.UsageError{Err: err}
		}
		if quiet, err = boolKey(l.k, "quiet"); err != nil {
			return &app.UsageError{Err: err}
		}

		vChanged, qChanged := cmd.Flags().Changed("verbose"), cmd.Flags().Changed("quiet")
		switch {
		case vChanged && qChanged && quiet && verbose > 0:
			return &app.UsageError{Err: errors.New("-q and -v are mutually exclusive")}
		case vChanged && !qChanged:
			quiet = false // explicit -v overrides env/file quiet
		case qChanged && !vChanged:
			verbose = 0 // explicit -q overrides env/file verbose
		case quiet && verbose > 0:
			verbose = 0 // both from env/file: quiet wins (less noise is the safe default)
		}
	}

	level := slog.LevelInfo
	switch {
	case quiet:
		level = slog.LevelError
	case verbose >= 1:
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{
		Level:     level,
		AddSource: verbose >= 2,
	})
	slog.SetDefault(slog.New(handler))
	return nil
}

// checkPProfForm rejects the space-separated `--pprof addr` spelling early
// with a precise error. --pprof uses NoOptDefVal (bare flag = localhost:6060),
// so pflag would otherwise treat a following "host:port" token as a
// positional argument — on `airom k8s` it would silently become the
// kubeconfig context while pprof binds the default port.
func checkPProfForm(args []string) error {
	for i, a := range args {
		if a == "--" {
			break
		}
		if a == "--pprof" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			next := args[i+1]
			if _, port, err := net.SplitHostPort(next); err == nil && port != "" {
				return fmt.Errorf("--pprof %s: an explicit address must be attached with '=' (--pprof=%s)", next, next)
			}
		}
	}
	return nil
}
