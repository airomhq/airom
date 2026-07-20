package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// SourceKind identifies which acquisition strategy a scan uses
// (ARCHITECTURE.md §7). The CLI resolves a command (and, for `airom scan`,
// the target's detected scheme) into exactly one SourceKind.
type SourceKind string

// The four source kinds map 1:1 onto the acquisition implementations under
// internal/source (§7).
const (
	SourceFS    SourceKind = "fs"
	SourceRepo  SourceKind = "repo"
	SourceImage SourceKind = "image"
	SourceK8s   SourceKind = "k8s"
)

// OutputFormat enumerates the writer formats (ARCHITECTURE.md §11). The
// writer implementations land in Phase 7; this enum is the CLI-facing
// contract and MUST stay in sync with the writer registry once it exists
// (reconciled in Phase 7).
type OutputFormat string

// The five v1 writer formats (§11); SPDX is a reserved v2 slot.
const (
	FormatTable     OutputFormat = "table"
	FormatJSON      OutputFormat = "json"
	FormatCycloneDX OutputFormat = "cyclonedx"
	FormatSARIF     OutputFormat = "sarif"
	FormatYAML      OutputFormat = "yaml"
)

// Formats lists every valid output format, sorted, for error messages and
// completion.
func Formats() []string {
	fs := []string{
		string(FormatTable), string(FormatJSON), string(FormatCycloneDX),
		string(FormatSARIF), string(FormatYAML),
	}
	sort.Strings(fs)
	return fs
}

// ParseFormat validates a user-supplied format name.
func ParseFormat(s string) (OutputFormat, error) {
	switch OutputFormat(strings.ToLower(strings.TrimSpace(s))) {
	case FormatTable:
		return FormatTable, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatCycloneDX:
		return FormatCycloneDX, nil
	case FormatSARIF:
		return FormatSARIF, nil
	case FormatYAML:
		return FormatYAML, nil
	default:
		return "", fmt.Errorf("unknown output format %q (valid: %s)", s, strings.Join(Formats(), ", "))
	}
}

// OutputSpec is one resolved "-o fmt[=path]" destination. An empty Path
// means stdout. At most one spec per scan may write to stdout (validated).
type OutputSpec struct {
	Format OutputFormat
	Path   string
}

func (o OutputSpec) String() string {
	if o.Path == "" {
		return string(o.Format)
	}
	return string(o.Format) + "=" + o.Path
}

// Config is the fully-resolved input to a scan: the single value the
// composition root consumes (ARCHITECTURE.md §12). The CLI owns building it
// (flags > AIROM_* env > .airom.yaml > defaults); nothing downstream reads
// flags, env, or files.
type Config struct {
	Source SourceKind
	Target string

	// Output & selection
	Outputs   []OutputSpec
	Select    string   // detector selection expression (Syft-style; applied in Phase 5)
	RulePaths []string // --rules overlays (loaded in Phase 6)

	// Performance knobs (invariant P2: peak memory is a function of these,
	// never of input size)
	Parallel    int   // worker count; 0 -> GOMAXPROCS via ApplyDefaults
	IOBudget    int64 // byte-weighted I/O semaphore budget, bytes
	MaxFileSize int64 // full-content read cap for text detectors, bytes

	// Presentation
	MinConfidence float64

	// Walking & cache
	IgnoreGlobs []string
	CacheDir    string
	NoCache     bool

	// Writers
	CDXVersion       string
	SARIFStrictKinds bool

	// CI policy (exit-code contract in docs/cli.md). Nil Policy = no gate:
	// scan success always exits 0 regardless of findings.
	Policy   *Policy
	ExitCode int

	// Presentation. Quiet mirrors -q; NoProgress suppresses the scan spinner.
	// Both are stderr-only concerns and never affect the emitted AIBOM.
	Quiet      bool
	NoProgress bool

	// Run environment
	Offline   bool
	PProfAddr string
	TraceFile string
	Stats     bool

	// image-specific
	ImageInput    string
	ImagePlatform string

	// k8s-specific
	K8sContext        string
	K8sNamespace      string
	K8sAllNamespaces  bool
	K8sManifests      string
	K8sParallelImages bool
}

// Documented defaults (docs/cli.md "Global flags"). Single source of truth:
// the CLI derives its flag-default strings from these constants, so the two
// paths (CLI and future library embedding) cannot drift.
const (
	DefaultIOBudget    int64 = 256 << 20 // 256m
	DefaultMaxFileSize int64 = 1 << 20   // 1m
	DefaultCDXVersion        = "1.6"
)

// DefaultCacheDir is <user cache dir>/airom, falling back to a temp-dir
// location when the OS cache dir cannot be determined.
func DefaultCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "airom-cache")
	}
	return filepath.Join(base, "airom")
}

// ApplyDefaults fills unset (zero) values with the documented defaults
// (docs/cli.md, "Global flags"). It only fills true zero values: a negative
// Parallel or size survives to Validate and is rejected there, never
// silently normalized. ExitCode is NOT defaulted here — the CLI resolves
// the documented "1 when a policy is active" default explicitly, so that an
// explicit --exit-code 0 with an active policy means "evaluate and report,
// but never fail the build" (the standard scanner idiom).
func (c *Config) ApplyDefaults() {
	if c.Parallel == 0 {
		c.Parallel = runtime.GOMAXPROCS(0)
	}
	if c.IOBudget == 0 {
		c.IOBudget = DefaultIOBudget
	}
	if c.MaxFileSize == 0 {
		c.MaxFileSize = DefaultMaxFileSize
	}
	if c.CacheDir == "" {
		c.CacheDir = DefaultCacheDir()
	}
	if c.CDXVersion == "" {
		c.CDXVersion = DefaultCDXVersion
	}
	if len(c.Outputs) == 0 {
		c.Outputs = []OutputSpec{{Format: FormatTable}}
	}
}

// Validate rejects configurations the engine must never see. Violations are
// usage errors (exit code 2 per the docs/cli.md contract).
func (c *Config) Validate() error {
	switch c.Source {
	case SourceFS, SourceRepo, SourceImage, SourceK8s:
	default:
		return fmt.Errorf("internal: unknown source kind %q", c.Source)
	}
	if c.Source != SourceK8s && c.Target == "" && c.ImageInput == "" {
		return fmt.Errorf("no scan target given")
	}
	if c.Source == SourceImage && c.Target != "" && c.ImageInput != "" {
		return fmt.Errorf("image: a reference and --input are mutually exclusive")
	}
	if c.Source == SourceK8s && c.K8sNamespace != "" && c.K8sAllNamespaces {
		return fmt.Errorf("k8s: --namespace and --all-namespaces are mutually exclusive")
	}
	if c.Parallel < 0 {
		return fmt.Errorf("--parallel must be >= 0, got %d", c.Parallel)
	}
	if c.IOBudget < 0 {
		return fmt.Errorf("--io-budget must be >= 0, got %d", c.IOBudget)
	}
	if c.MaxFileSize < 0 {
		return fmt.Errorf("--max-file-size must be >= 0, got %d", c.MaxFileSize)
	}
	if c.MinConfidence < 0 || c.MinConfidence > 1 {
		return fmt.Errorf("--min-confidence must be in [0,1], got %v", c.MinConfidence)
	}
	if c.CDXVersion != "1.6" && c.CDXVersion != "1.7" {
		return fmt.Errorf("--cdx-version must be 1.6 or 1.7, got %q", c.CDXVersion)
	}
	stdout := 0
	for _, o := range c.Outputs {
		if _, err := ParseFormat(string(o.Format)); err != nil {
			return err
		}
		if o.Path == "" {
			stdout++
		}
	}
	if stdout > 1 {
		return fmt.Errorf("at most one output may write to stdout; give the others a path (-o fmt=path)")
	}
	if c.ExitCode < 0 || c.ExitCode > 255 {
		return fmt.Errorf("--exit-code must be in [0,255], got %d", c.ExitCode)
	}
	return nil
}
