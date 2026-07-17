package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/Roro1727/airom/internal/metrics"
	"github.com/Roro1727/airom/internal/source/dirsource"
	"github.com/Roro1727/airom/internal/source/gitsource"
	"github.com/Roro1727/airom/internal/source/imagesource"
	"github.com/Roro1727/airom/internal/source/k8ssource"
	"github.com/Roro1727/airom/pkg/airom"
)

// UsageError marks configuration and flag errors: the CLI maps it (like any
// fatal error) to exit code 2 per the docs/cli.md contract, but prefixes the
// message differently from runtime failures.
type UsageError struct{ Err error }

func (e *UsageError) Error() string { return e.Err.Error() }
func (e *UsageError) Unwrap() error { return e.Err }

// PolicyExit signals that the scan completed successfully AND the opt-in
// --fail-on/--exit-code gate matched the assembled inventory. It is NOT a
// fatal error — the scan and all output finished normally; the CLI unwraps it
// and returns Code as the process exit status (docs/cli.md exit-code
// contract). Fatal errors map to exit 2; this carries the user's chosen gate
// code (default 1).
type PolicyExit struct{ Code int }

func (e *PolicyExit) Error() string { return fmt.Sprintf("policy matched; exit %d", e.Code) }

// gate evaluates the configured CI policy against the assembled inventory,
// after all output has been emitted. A nil policy (no --fail-on/--exit-code)
// never gates. A match surfaces cfg.ExitCode via the PolicyExit sentinel.
func gate(inv *airom.Inventory, cfg *Config) error {
	if cfg.Policy == nil {
		return nil
	}
	if cfg.Policy.Matches(inv) {
		return &PolicyExit{Code: cfg.ExitCode}
	}
	return nil
}

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
	case SourceRepo:
		return runRepo(ctx, cfg)
	case SourceImage:
		return runImage(ctx, cfg)
	case SourceK8s:
		return runK8s(ctx, cfg)
	default:
		return fmt.Errorf("cannot run %s scan of %q: %w", cfg.Source, cfg.Target, ErrEngineNotWired)
	}
}

// runFS executes a real filesystem scan through the full framework
// pipeline: dispatch (phase 1) → project detectors (phase 2) → assembly.
func runFS(ctx context.Context, cfg *Config) error {
	src, err := dirsource.New(cfg.Target, dirsource.Options{IgnoreGlobs: cfg.IgnoreGlobs})
	if err != nil {
		return &UsageError{Err: err} // source acquisition failure = fatal (P6)
	}
	defer func() { _ = src.Close() }()

	inv, err := runScanPipeline(ctx, cfg, src)
	if err != nil {
		return err
	}

	if err := emit(ctx, inv, cfg); err != nil {
		return err
	}
	return gate(inv, cfg)
}

// runRepo scans a git repository: a remote URL is shallow-cloned (exec-git),
// a local path is scanned as its worktree; git provenance feeds the output.
func runRepo(ctx context.Context, cfg *Config) error {
	src, err := gitsource.New(cfg.Target, gitsource.Options{IgnoreGlobs: cfg.IgnoreGlobs})
	if err != nil {
		return &UsageError{Err: err}
	}
	defer func() { _ = src.Close() }()

	inv, err := runScanPipeline(ctx, cfg, src)
	if err != nil {
		return err
	}
	if err := emit(ctx, inv, cfg); err != nil {
		return err
	}
	return gate(inv, cfg)
}

// runImage scans a container image: a saved archive (--input) or an OCI
// layout / image reference. The squashed filesystem is streamed once.
func runImage(ctx context.Context, cfg *Config) error {
	var (
		src *imagesource.Source
		err error
	)
	opts := imagesource.Options{IgnoreGlobs: cfg.IgnoreGlobs}
	if cfg.ImageInput != "" {
		src, err = imagesource.NewFromTar(cfg.ImageInput, opts)
	} else {
		src, err = imagesource.New(cfg.Target, opts)
	}
	if err != nil {
		return &UsageError{Err: err}
	}
	defer func() { _ = src.Close() }()

	inv, err := runScanPipeline(ctx, cfg, src)
	if err != nil {
		return err
	}
	if err := emit(ctx, inv, cfg); err != nil {
		return err
	}
	return gate(inv, cfg)
}

// runK8s scans Kubernetes workloads. Offline manifest mode (--manifests)
// enumerates workload images; each unique image is then scanned. Live-cluster
// mode is not yet wired (k8ssource reports so).
func runK8s(ctx context.Context, cfg *Config) error {
	src, err := k8ssource.New(k8ssource.Options{ManifestsDir: cfg.K8sManifests})
	if err != nil {
		return &UsageError{Err: err}
	}
	images := src.Images()
	fmt.Fprintf(stdout, "airom: k8s scan of %s\n", cfg.K8sManifests)
	fmt.Fprintf(stdout, "  workload images: %d\n", len(images))
	for _, img := range src.Details() {
		fmt.Fprintf(stdout, "    %s  (%d workload(s))\n", img.Ref, len(img.Workloads))
	}
	if len(images) == 0 {
		return nil
	}

	imgOpts := imagesource.Options{IgnoreGlobs: cfg.IgnoreGlobs}
	var scanErrs []string
	var gateErr error // the gate trips if ANY scanned image matches the policy
	for _, ref := range images {
		isrc, ierr := imagesource.New(ref, imgOpts)
		if ierr != nil {
			scanErrs = append(scanErrs, fmt.Sprintf("%s: %v", ref, ierr))
			continue
		}
		inv, serr := runScanPipeline(ctx, cfg, isrc)
		_ = isrc.Close()
		if serr != nil {
			scanErrs = append(scanErrs, fmt.Sprintf("%s: %v", ref, serr))
			continue
		}
		fmt.Fprintf(stdout, "\n=== image %s ===\n", ref)
		if err := emit(ctx, inv, cfg); err != nil {
			return err
		}
		if gerr := gate(inv, cfg); gerr != nil {
			gateErr = gerr
		}
	}
	if len(scanErrs) > 0 {
		slog.Warn("k8s: some images could not be scanned", "count", len(scanErrs))
		for _, e := range scanErrs {
			slog.Warn("k8s image", "error", e)
		}
	}
	return gateErr
}

// logDiagnostics surfaces assembler warnings and, under --stats or when
// present, the Unknown records to the log — the writers carry the graph
// itself, the log carries the honesty channel.
func logDiagnostics(inv *airom.Inventory, cfg *Config) {
	if cfg.Stats || len(inv.Unknowns) > 0 {
		for _, u := range inv.Unknowns {
			slog.Warn("unknown", "path", u.Path, "detector", u.DetectorID, "reason", u.Reason)
		}
	}
	for _, w := range inv.Stats.Warnings {
		slog.Warn("assembler", "warning", w)
	}
}
