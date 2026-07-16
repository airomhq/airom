package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/Roro1727/airom/internal/engine"
	"github.com/Roro1727/airom/internal/metrics"
	"github.com/Roro1727/airom/internal/source/dirsource"
)

// UsageError marks configuration and flag errors: the CLI maps it (like any
// fatal error) to exit code 2 per the docs/cli.md contract, but prefixes the
// message differently from runtime failures.
type UsageError struct{ Err error }

func (e *UsageError) Error() string { return e.Err.Error() }
func (e *UsageError) Unwrap() error { return e.Err }

// ErrEngineNotWired reports that a source behind the CLI surface is not yet
// assembled: fs scans run for real as of Phase 4; the repo, image, and k8s
// sources land in Phase 6 per docs/ROADMAP.md. Until then those commands
// fail fast with this error instead of pretending to scan.
var ErrEngineNotWired = errors.New("source not wired yet")

// stdout is the summary destination, injectable for tests.
var stdout io.Writer = os.Stdout

// Run executes one scan described by cfg: it is the single entry point the
// CLI (and pkg/airom.Scan, later) calls. It owns defaulting, validation,
// run-environment bootstrap (pprof/trace), and the source dispatch.
func Run(ctx context.Context, cfg *Config) error {
	if err := ctx.Err(); err != nil {
		return err // honor a context canceled before we started
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return &UsageError{Err: err}
	}

	stop, err := metrics.Bootstrap(metrics.Options{
		PProfAddr: cfg.PProfAddr,
		TraceFile: cfg.TraceFile,
	})
	if err != nil {
		return fmt.Errorf("bootstrap profiling: %w", err)
	}
	defer stop()

	switch cfg.Source {
	case SourceFS:
		return runFS(ctx, cfg)
	default:
		// TODO(phase-6): wire gitsource, imagesource, and k8ssource.
		// Suggested tracking issue: "Phase 6: implement the repo, image,
		// and k8s sources".
		return fmt.Errorf("cannot run %s scan of %q: %w (this source arrives in Phase 6; see docs/ROADMAP.md)",
			cfg.Source, cfg.Target, ErrEngineNotWired)
	}
}

// runFS executes a real filesystem scan. Until the detector framework lands
// (Phase 5) the processor is nil: the pipeline walks, classifies, and
// reports honestly that zero detectors ran — a useful ignore-rule dry run.
func runFS(ctx context.Context, cfg *Config) error {
	src, err := dirsource.New(cfg.Target, dirsource.Options{IgnoreGlobs: cfg.IgnoreGlobs})
	if err != nil {
		return &UsageError{Err: err} // source acquisition failure = fatal (P6)
	}
	defer func() { _ = src.Close() }()

	eng := engine.New(engine.Options{
		Parallel:    cfg.Parallel,
		IOBudget:    cfg.IOBudget,
		MaxFileSize: cfg.MaxFileSize,
	})
	out, err := eng.Scan(ctx, src, nil)
	if err != nil {
		return fmt.Errorf("scan %q: %w", cfg.Target, err)
	}

	printSummary(out, cfg)
	return nil
}

// printSummary is the interim scan report: the table/CycloneDX/SARIF
// writers land in Phase 7; until then the scan reports its own honesty
// counters (never pretending components were looked for).
func printSummary(out *engine.Outcome, cfg *Config) {
	fmt.Fprintf(stdout, "airom: scan of %s complete\n", cfg.Target)
	fmt.Fprintf(stdout, "  files walked:  %d\n", out.Stats.FilesWalked)
	fmt.Fprintf(stdout, "  bytes read:    %d header, %d content\n", out.Stats.HeaderBytes, out.Stats.ContentBytes)
	fmt.Fprintf(stdout, "  unknowns:      %d\n", len(out.Unknowns))
	fmt.Fprintf(stdout, "  duration:      %s\n", out.Stats.Duration.Round(time.Millisecond))
	fmt.Fprintf(stdout, "  components:    0 — no detectors registered yet (framework lands in Phase 5; writers in Phase 7)\n")
	if cfg.Stats || len(out.Unknowns) > 0 {
		for _, u := range out.Unknowns {
			slog.Warn("unknown", "path", u.Path, "stage", u.Stage, "reason", u.Reason)
		}
	}
}
