package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/Roro1727/airom/internal/app"
	"github.com/Roro1727/airom/internal/source"
)

// exactArgs mirrors cobra.ExactArgs(1) but keeps a usage hint in the
// error, since SilenceUsage suppresses cobra's own help echo. Every current
// command takes at most one positional, so the count is fixed.
func exactArgs(what string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return &app.UsageError{Err: fmt.Errorf("%s requires %s (got %d)\nRun '%s --help' for usage",
				cmd.Name(), what, len(args), cmd.CommandPath())}
		}
		return nil
	}
}

// maxArgs mirrors cobra.MaximumNArgs with the same usage-hint treatment.
func maxArgs(n int, what string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) > n {
			return &app.UsageError{Err: fmt.Errorf("%s accepts %s (got %d)\nRun '%s --help' for usage",
				cmd.Name(), what, len(args), cmd.CommandPath())}
		}
		return nil
	}
}

// runWith resolves configuration for a scan-family command and hands off to
// the composition root.
func runWith(cmd *cobra.Command, src app.SourceKind, target string) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("determine working directory: %w", err)
	}
	cfg, err := buildConfig(cmd.Flags(), wd, src, target)
	if err != nil {
		return err
	}
	return runScan(cmd.Context(), cfg)
}

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan <target>",
		Short: "Scan a target with scheme auto-detection (dir | git URL | image ref)",
		Long: `Scan auto-detects the target scheme in order: existing local path -> git URL
-> image reference. Explicit prefixes force interpretation: dir:, repo:, image:.`,
		Args: exactArgs("exactly one <target>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, target, err := source.DetectTarget(args[0])
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
			return runWith(cmd, src, target)
		},
	}
}

func newFSCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fs <path>",
		Short: "Scan a directory tree",
		Args:  exactArgs("exactly one <path>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(args[0]); err != nil {
				return &app.UsageError{Err: fmt.Errorf("cannot scan %q: %w", args[0], err)}
			}
			return runWith(cmd, app.SourceFS, args[0])
		},
	}
}

func newRepoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "repo <url|path>",
		Short: "Scan a git repository (remote URL: shallow clone; local path: worktree)",
		Args:  exactArgs("exactly one <url|path>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWith(cmd, app.SourceRepo, args[0])
		},
	}
}

func newImageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image [ref]",
		Short: "Scan a container image (registry, daemon, tarball, or OCI layout)",
		Args:  maxArgs(1, "at most one [ref]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			var ref string
			if len(args) == 1 {
				ref = args[0]
			}
			// Build the layered config FIRST so an --input supplied via
			// AIROM_INPUT or .airom.yaml participates in the validation
			// (Config.Validate enforces the mutual exclusion as a backstop).
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("determine working directory: %w", err)
			}
			cfg, err := buildConfig(cmd.Flags(), wd, app.SourceImage, ref)
			if err != nil {
				return err
			}
			switch {
			case ref == "" && cfg.ImageInput == "":
				return &app.UsageError{Err: fmt.Errorf("image: give a reference or --input <tar>")}
			case ref != "" && cfg.ImageInput != "":
				// Config.Validate enforces this too; failing here gives the
				// error before any engine work regardless of which layer
				// (flag, AIROM_INPUT, .airom.yaml) supplied input.
				return &app.UsageError{Err: fmt.Errorf("image: a reference and --input are mutually exclusive")}
			}
			return runScan(cmd.Context(), cfg)
		},
	}
	cmd.Flags().String("input", "", "scan a saved image tarball (docker save / OCI archive); no network")
	cmd.Flags().String("platform", "", "platform to select from a multi-arch index (e.g. linux/arm64)")
	return cmd
}

func newK8sCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "k8s [context]",
		Short: "Scan the images of Kubernetes workloads (or manifest files with --manifests)",
		Args:  maxArgs(1, "at most one [context]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("determine working directory: %w", err)
			}
			var kubeContext string
			if len(args) == 1 {
				kubeContext = args[0]
			}
			cfg, err := buildConfig(cmd.Flags(), wd, app.SourceK8s, kubeContext)
			if err != nil {
				return err
			}
			cfg.K8sContext = kubeContext
			return runScan(cmd.Context(), cfg)
		},
	}
	cmd.Flags().String("namespace", "", "restrict to one namespace")
	cmd.Flags().BoolP("all-namespaces", "A", false, "all namespaces")
	cmd.Flags().String("manifests", "", "offline mode: extract image refs from manifest YAML in dir")
	cmd.Flags().Bool("parallel-images", false, "scan images concurrently (serial by default)")
	return cmd
}

func newCleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clean",
		Short: "Remove the scan cache",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("determine working directory: %w", err)
			}
			l, err := loadLayers(cmd.Flags(), wd)
			if err != nil {
				return err
			}
			dir := l.k.String("cache-dir")
			if dir == "" {
				dir = app.DefaultCacheDir()
			}
			abs, err := filepath.Abs(dir)
			if err != nil {
				return fmt.Errorf("resolve cache dir: %w", err)
			}
			if err := guardCacheRemoval(abs); err != nil {
				return err
			}
			if _, err := os.Stat(abs); os.IsNotExist(err) {
				fmt.Fprintf(cmd.OutOrStdout(), "no cache at %s\n", abs)
				return nil
			}
			if err := os.RemoveAll(abs); err != nil {
				return fmt.Errorf("remove cache: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed cache at %s\n", abs)
			return nil
		},
	}
}

// guardCacheRemoval refuses catastrophic RemoveAll targets. Three layers of
// defense (each independently sufficient for its failure mode):
//
//  1. Basename allowlist: only directories the tool itself creates ("airom"
//     from DefaultCacheDir, "airom-cache" from the temp fallback) may be
//     removed — an arbitrary --cache-dir typo can never delete user data.
//  2. Filesystem-identity check against $HOME and the volume root via
//     os.SameFile — immune to case-insensitive filesystems (macOS APFS
//     default), symlinked $HOME, and firmlink aliasing, where naive string
//     comparison is bypassable by a one-character case typo.
//  3. abs is Lstat'ed (not Stat'ed): a symlink passed as --cache-dir is
//     compared as the link itself, matching RemoveAll's unlink-only behavior.
func guardCacheRemoval(abs string) error {
	if base := filepath.Base(abs); base != "airom" && base != "airom-cache" {
		return &app.UsageError{Err: fmt.Errorf(
			"refusing to remove %q: not an airom cache directory (basename must be \"airom\" or \"airom-cache\"); delete it manually if you really mean it", abs)}
	}

	sameAs := func(guard string) bool {
		if abs == guard {
			return true
		}
		gi, err := os.Stat(guard) // follow a symlinked $HOME to its target
		if err != nil {
			return false
		}
		ai, err := os.Lstat(abs) // do NOT follow abs (see rule 3 above)
		if err != nil {
			return false
		}
		return os.SameFile(gi, ai)
	}

	if home, err := os.UserHomeDir(); err == nil && sameAs(home) {
		return &app.UsageError{Err: fmt.Errorf("refusing to remove home directory %q as a cache dir", abs)}
	}
	root := filepath.VolumeName(abs) + string(filepath.Separator)
	if abs == root || sameAs(root) {
		return &app.UsageError{Err: fmt.Errorf("refusing to remove filesystem root as a cache dir")}
	}
	return nil
}

func newVersionCmd(bi BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build date (the ToolInfo embedded in every AIBOM)",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "airom %s\n", bi.Version)
			fmt.Fprintf(w, "  commit: %s\n", bi.Commit)
			fmt.Fprintf(w, "  built:  %s\n", bi.Date)
			fmt.Fprintf(w, "  go:     %s (%s/%s)\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}
}
