package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/airomhq/airom/internal/compliance"
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

// The writer formats (§11).
const (
	FormatTable      OutputFormat = "table"
	FormatJSON       OutputFormat = "json"
	FormatCycloneDX  OutputFormat = "cyclonedx"
	FormatSARIF      OutputFormat = "sarif"
	FormatYAML       OutputFormat = "yaml"
	FormatCompliance OutputFormat = "compliance"
	FormatVEX        OutputFormat = "vex"
	FormatSPDX       OutputFormat = "spdx"
	FormatSPDX3      OutputFormat = "spdx3"
)

// Formats lists every valid output format, sorted, for error messages and
// completion.
func Formats() []string {
	fs := []string{
		string(FormatTable), string(FormatJSON), string(FormatCycloneDX),
		string(FormatSARIF), string(FormatYAML), string(FormatCompliance),
		string(FormatVEX), string(FormatSPDX), string(FormatSPDX3),
	}
	sort.Strings(fs)
	return fs
}

// ComplianceFrameworks lists the embedded compliance framework ids, sorted —
// for the --compliance flag usage string and error messages.
func ComplianceFrameworks() []string { return compliance.IDs() }

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
	case FormatCompliance:
		return FormatCompliance, nil
	case FormatVEX:
		return FormatVEX, nil
	case FormatSPDX:
		return FormatSPDX, nil
	case FormatSPDX3:
		return FormatSPDX3, nil
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
	Outputs    []OutputSpec
	Select     string   // detector selection expression (Syft-style; applied in Phase 5)
	RulePaths  []string // --rules overlays (loaded in Phase 6)
	Compliance []string // --compliance framework ids (e.g. "nist-ai-rmf"); empty = off
	CVE        bool     // match package purls against OSV.dev (on by default; off under --no-cve/--offline)

	// NoEOL disables the hosted-model end-of-life overlay, which is otherwise
	// always on. Unlike the CVE overlay this needs no network — the catalog is
	// embedded — so it runs under --offline too, and the field is negative so a
	// zero-value Config gets the documented default (on).
	NoEOL bool

	// IncludeTests keeps components whose every occurrence is test scaffolding
	// in the default view. They are always detected and always present in the
	// native document (Component.TestOnly); this only decides whether the
	// attention surfaces — table, SARIF, and the --fail-on gate — count them.
	//
	// Off by default because an AIBOM answers "what AI does this software use?"
	// and a rule-pack fixture is not an answer: scanning AIROM's own repository
	// produced 185 components, 180 of them fixtures. On when a reviewer's
	// question is instead "what do our tests reach for?" — a test calling a live
	// model is still a real key and a real bill.
	IncludeTests bool

	// Now pins the scan clock. Zero means the wall clock. It exists so a scan
	// can be a pure function of its inputs: the EOL overlay's answer depends on
	// the date ("is this shutdown in the past yet?"), so a golden suite must be
	// able to fix the day the way it already fixes the rule cache.
	Now time.Time

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
	Wide             bool // table: expand every file:line occurrence under each component

	// Rule updates (Model B). NoCachedRules forces scans onto the embedded
	// packs, ignoring any fetched bundle. RulesSource/InsecureSkipSignature
	// only affect `airom rules update`.
	NoCachedRules         bool
	RulesSource           string
	InsecureSkipSignature bool

	// AutoUpdateRules refreshes the cached bundle before a scan, at most once
	// a day. The zero value is OFF on purpose: the CLI turns it on, so a test
	// or an embedder that builds a Config directly never touches the network.
	// Ignored under Offline, NoCachedRules, or a CI environment.
	AutoUpdateRules bool

	// Remediation (docs/cve.md "Fixing what it finds"). Fix opens the
	// interactive advisory table after the scan; FixAll applies every fixable
	// pin without one. Both rewrite manifests on disk, which is why they are
	// opt-in flags rather than a default: a scanner that edits your tree
	// unasked is not a scanner.
	//
	// They are mutually exclusive (Validate enforces it) and require the CVE
	// overlay — with no advisories there is nothing to fix — and a filesystem
	// scan, because a container layer and a shallow clone are not the tree the
	// user would commit.
	Fix    bool
	FixAll bool

	// FixVerify runs each edited manifest through its ecosystem's resolver in
	// dry-run mode after the fixes land, so a bump that clears eight CVEs and
	// leaves a manifest nothing can install is caught here rather than in
	// somebody's next build. Needs the network and the toolchain; every failure
	// to run degrades to "not checked", never to a false all-clear.
	FixVerify bool

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
//
// Indirected through a var so the test binary can redirect it. ApplyDefaults
// copies this into Config.CacheDir, and a cached rule bundle OVERRIDES the
// embedded packs — so without the seam, the ruleset a test scans with depends
// on whether the developer has ever run `airom rules update`. Auto-update makes
// that the normal state of a machine rather than a rare one.
func DefaultCacheDir() string { return defaultCacheDir() }

var defaultCacheDir = func() string {
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
	// The CVE overlay needs the network; --offline always wins over it. The CLI
	// already computes CVE this way, but enforce it here too so a programmatic
	// Config{CVE: true, Offline: true} degrades to offline rather than trying to
	// reach OSV.dev.
	if c.Offline {
		c.CVE = false
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
	// Gating on compliance you never evaluated is CI theater: the gate would
	// silently never fire. Require --compliance whenever --fail-on names it.
	if c.Policy.ReferencesCompliance() && len(c.Compliance) == 0 {
		return fmt.Errorf("--fail-on references compliance but no --compliance framework was given")
	}
	// Gating on CVEs while the overlay is disabled is CI theater — the gate would
	// silently never fire. The overlay is on by default, so this only trips when
	// the user turned it off with --no-cve or --offline. (ApplyDefaults has
	// already forced CVE off under --offline.)
	if c.Policy.ReferencesCVE() && !c.CVE {
		return fmt.Errorf("--fail-on references cve but the CVE overlay is disabled (remove --no-cve, or drop --offline)")
	}
	// Same rule for the lifecycle overlay: gating on findings the scan was told
	// not to produce is a gate that can only ever pass.
	if c.Policy.ReferencesEOL() && c.NoEOL {
		return fmt.Errorf("--fail-on references eol but the model lifecycle overlay is disabled (remove --no-eol)")
	}
	if err := c.validateFix(); err != nil {
		return err
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

// validateFix rejects the flag combinations where a fix could not do what the
// user is asking for. Each one fails loudly instead of running a scan and then
// quietly remediating nothing.
func (c *Config) validateFix() error {
	if !c.Fix && !c.FixAll {
		if c.FixVerify {
			return fmt.Errorf("--fix-verify verifies the fixes --fix or --fix-all made; neither was given")
		}
		return nil
	}
	if c.Fix && c.FixAll {
		return fmt.Errorf("--fix and --fix-all are mutually exclusive: --fix opens the table, --fix-all skips it")
	}
	flag := "--fix"
	if c.FixAll {
		flag = "--fix-all"
	}
	// Offline is checked BEFORE the overlay: ApplyDefaults already forced CVE
	// off under --offline, so the overlay message would otherwise fire first and
	// this specific one could never be reached — telling a user who asked for
	// --fix-verify --offline about the CVE overlay instead of about the resolver
	// they just asked to run without a network.
	if c.FixVerify && c.Offline {
		return fmt.Errorf("--fix-verify runs a dependency resolver, which needs the network (drop --offline)")
	}
	if !c.CVE {
		return fmt.Errorf("%s needs the CVE overlay to have something to fix (remove --no-cve, or drop --offline)", flag)
	}
	if c.Source != SourceFS {
		return fmt.Errorf("%s rewrites manifests in a working tree, so it only applies to a filesystem scan (got a %s scan)", flag, c.Source)
	}
	return nil
}
