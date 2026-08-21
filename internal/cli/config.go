package cli

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	kyaml "github.com/knadh/koanf/parsers/yaml"
	kfile "github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"

	"github.com/airomhq/airom/internal/app"
)

// configFileName is discovered in the working directory (docs/cli.md).
const configFileName = ".airom.yaml"

// knownKeys is the closed set of configuration keys accepted from
// .airom.yaml and the AIROM_* environment: every global flag plus the
// command-specific keys. A typo'd key is a fatal configuration error
// (exit 2), never a silent no-op — the same contract flags already have.
var knownKeys = map[string]bool{
	// global flags (flags.go)
	"output": true, "format": true, "select": true, "rules": true,
	"compliance": true, "cve": true, "no-cve": true, "no-eol": true,
	"include-tests": true, "fix": true, "fix-all": true, "fix-verify": true,
	"parallel": true, "io-budget": true, "max-file-size": true,
	"min-confidence": true, "ignore": true, "cache-dir": true,
	"no-cache": true, "cdx-version": true, "sarif-strict-kinds": true,
	"exit-code": true, "fail-on": true, "offline": true, "pprof": true,
	"trace": true, "stats": true, "verbose": true, "quiet": true,
	"no-progress": true, "wide": true,
	"no-cached-rules": true, "rules-source": true, "insecure-skip-signature": true,
	"auto-update-rules": true,
	// command-specific (image, k8s)
	"input": true, "platform": true, "namespace": true,
	"all-namespaces": true, "manifests": true, "parallel-images": true,
}

// listKeys are configuration keys whose env-variable form is comma-split
// (AIROM_OUTPUT="table,sarif=airom.sarif").
var listKeys = map[string]bool{
	"output":     true,
	"rules":      true,
	"compliance": true,
	"ignore":     true,
}

// layers is the merged configuration plus per-layer provenance, needed
// where CROSS-KEY precedence matters (an env-provided --format alias must
// beat a file-provided output: list; same-key precedence is handled by the
// merge order itself).
type layers struct {
	k   *koanf.Koanf // merged: flag defaults < .airom.yaml < AIROM_* env < set flags
	env *koanf.Koanf // env layer alone
}

// loadLayers layers configuration in the documented precedence order,
// lowest first: flag defaults (via posflag fill-in) < .airom.yaml < AIROM_*
// env < explicitly-set flags. dir is the directory searched for .airom.yaml
// (injectable for tests).
func loadLayers(flags *pflag.FlagSet, dir string) (*layers, error) {
	k := koanf.New(".")

	path := filepath.Join(dir, configFileName)
	if _, err := os.Stat(path); err == nil {
		fileK := koanf.New(".")
		if err := fileK.Load(kfile.Provider(path), kyaml.Parser()); err != nil {
			return nil, &app.UsageError{Err: fmt.Errorf("reading %s: %w", path, err)}
		}
		if err := checkKnownKeys(fileK, path+": unknown configuration key(s)"); err != nil {
			return nil, err
		}
		if err := k.Merge(fileK); err != nil {
			return nil, fmt.Errorf("merging %s: %w", path, err)
		}
	}

	envK := koanf.New(".")
	if err := envK.Load(envProvider{environ: os.Environ()}, nil); err != nil {
		return nil, fmt.Errorf("reading AIROM_* environment: %w", err)
	}
	if err := checkKnownKeys(envK, "unknown AIROM_* environment variable(s) for key(s)"); err != nil {
		return nil, err
	}
	if err := k.Merge(envK); err != nil {
		return nil, fmt.Errorf("merging environment: %w", err)
	}

	// posflag: explicitly-set flags always win; unset flag defaults fill
	// only keys nothing else provided.
	if err := k.Load(posflag.Provider(flags, ".", k), nil); err != nil {
		return nil, fmt.Errorf("reading flags: %w", err)
	}
	return &layers{k: k, env: envK}, nil
}

// checkKnownKeys rejects configuration keys outside the documented surface,
// so a typo (AIROM_PARALLELS=8, "parallels:" in the file) fails loudly instead
// of silently not applying.
func checkKnownKeys(k *koanf.Koanf, msg string) error {
	seen := map[string]bool{}
	var unknown []string
	for _, key := range k.Keys() {
		top, _, _ := strings.Cut(key, ".")
		if !knownKeys[top] && !seen[top] {
			seen[top] = true
			unknown = append(unknown, top)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return &app.UsageError{Err: fmt.Errorf("%s: %s", msg, strings.Join(unknown, ", "))}
	}
	return nil
}

// envProvider implements koanf.Provider over AIROM_* environment variables:
// AIROM_IO_BUDGET=512m -> io-budget=512m. List-valued keys are comma-split.
type envProvider struct{ environ []string }

func (p envProvider) ReadBytes() ([]byte, error) {
	return nil, errors.New("envProvider does not support ReadBytes")
}

func (p envProvider) Read() (map[string]any, error) {
	out := map[string]any{}
	for _, kv := range p.environ {
		name, val, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, "AIROM_") {
			continue
		}
		key := strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(name, "AIROM_")), "_", "-")
		if key == "" {
			continue
		}
		if listKeys[key] {
			parts := strings.Split(val, ",")
			list := make([]string, 0, len(parts))
			for _, p := range parts {
				if s := strings.TrimSpace(p); s != "" {
					list = append(list, s)
				}
			}
			out[key] = list
			continue
		}
		out[key] = val
	}
	return out, nil
}

// ── Strict typed readers ────────────────────────────────────────────────────
//
// koanf's own getters (k.Int, k.Bool, k.Float64) silently coerce unparseable
// values to zero — which would turn a typo'd AIROM_EXIT_CODE into a silently
// deleted CI gate. These readers fail loudly instead; failures surface as
// UsageError -> exit 2, the documented contract for invalid configuration.

func intKey(k *koanf.Koanf, key string) (int, error) {
	switch v := k.Get(key).(type) {
	case nil:
		return 0, nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		if v != math.Trunc(v) {
			return 0, fmt.Errorf("--%s: invalid integer %v", key, v)
		}
		return int(v), nil
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, fmt.Errorf("--%s: invalid integer %q", key, v)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("--%s: invalid integer value %v", key, v)
	}
}

func floatKey(k *koanf.Koanf, key string) (float64, error) {
	switch v := k.Get(key).(type) {
	case nil:
		return 0, nil
	case float64:
		return v, nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return 0, fmt.Errorf("--%s: invalid number %q", key, v)
		}
		return f, nil
	default:
		return 0, fmt.Errorf("--%s: invalid number value %v", key, v)
	}
}

func boolKey(k *koanf.Koanf, key string) (bool, error) {
	switch v := k.Get(key).(type) {
	case nil:
		return false, nil
	case bool:
		return v, nil
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return false, fmt.Errorf("--%s: invalid boolean %q (want true/false)", key, v)
		}
		return b, nil
	default:
		return false, fmt.Errorf("--%s: invalid boolean value %v", key, v)
	}
}

// stringsKey reads a list-valued key, accepting a bare scalar as a
// one-element list (`ignore: "**/fixtures/**"` in .airom.yaml), mirroring
// the env layer where a single un-comma'd value is a one-element list.
func stringsKey(k *koanf.Koanf, key string) []string {
	if s, ok := k.Get(key).(string); ok {
		if t := strings.TrimSpace(s); t != "" {
			return []string{t}
		}
		return nil
	}
	return k.Strings(key)
}

// ── Config assembly ─────────────────────────────────────────────────────────

// buildConfig assembles the *app.Config for a scan-family command from the
// fully-layered configuration. Command-specific flags (image --input, k8s
// --namespace, ...) flow through the same layering because cobra merges
// them into cmd.Flags() at execution time.
// reconcileVerbosity resolves -v and -q against each other and against the
// env/file layers, returning the effective pair.
//
// It lives here, called by both setupLogging and buildConfig, because verbosity
// has to mean ONE thing. When each derived it independently, `-v` against a
// file's `quiet: true` turned logging on (correct) while leaving Config.Quiet
// true, so the progress indicator stayed off — the opposite of what the user
// asked for, and invisible.
//
// An explicit flag beats the env/file layers; between two explicit flags, -q and
// -v contradict and are rejected; between two layered values, quiet wins because
// less noise is the safe default.
func reconcileVerbosity(flags *pflag.FlagSet, verbose int, quiet bool) (int, bool, error) {
	vChanged, qChanged := flags.Changed("verbose"), flags.Changed("quiet")
	switch {
	case vChanged && qChanged && quiet && verbose > 0:
		return 0, false, &app.UsageError{Err: errors.New("-q and -v are mutually exclusive")}
	case vChanged && !qChanged:
		quiet = false
	case qChanged && !vChanged:
		verbose = 0
	case quiet && verbose > 0:
		verbose = 0
	}
	return verbose, quiet, nil
}

func buildConfig(flags *pflag.FlagSet, workdir string, src app.SourceKind, target string) (*app.Config, error) {
	l, err := loadLayers(flags, workdir)
	if err != nil {
		return nil, err
	}
	k := l.k

	outputs, err := resolveOutputs(l, flags)
	if err != nil {
		return nil, &app.UsageError{Err: err}
	}

	ioBudget, err := parseSizeKey(k, "io-budget")
	if err != nil {
		return nil, &app.UsageError{Err: err}
	}
	maxFileSize, err := parseSizeKey(k, "max-file-size")
	if err != nil {
		return nil, &app.UsageError{Err: err}
	}

	parallel, err := intKey(k, "parallel")
	if err != nil {
		return nil, &app.UsageError{Err: err}
	}
	minConfidence, err := floatKey(k, "min-confidence")
	if err != nil {
		return nil, &app.UsageError{Err: err}
	}

	cveFlag := true // --cve defaults on; honored so an explicit false disables
	var noCache, sarifStrict, offline, noCVE, noEOL, includeTests, stats, wide, quiet, noProgress, k8sAll, k8sParallelImages bool
	var noCachedRules, insecureSkipSig, autoUpdateRules bool
	var doFix, doFixAll, doFixVerify bool
	for key, dst := range map[string]*bool{
		"no-cache":                &noCache,
		"sarif-strict-kinds":      &sarifStrict,
		"offline":                 &offline,
		"cve":                     &cveFlag,
		"no-cve":                  &noCVE,
		"no-eol":                  &noEOL,
		"include-tests":           &includeTests,
		"fix":                     &doFix,
		"fix-all":                 &doFixAll,
		"fix-verify":              &doFixVerify,
		"stats":                   &stats,
		"wide":                    &wide,
		"no-cached-rules":         &noCachedRules,
		"auto-update-rules":       &autoUpdateRules,
		"insecure-skip-signature": &insecureSkipSig,
		"quiet":                   &quiet,
		"no-progress":             &noProgress,
		"all-namespaces":          &k8sAll,
		"parallel-images":         &k8sParallelImages,
	} {
		v, err := boolKey(k, key)
		if err != nil {
			return nil, &app.UsageError{Err: err}
		}
		*dst = v
	}

	// Same rule the logger uses, from the same helper. Deriving `quiet` twice is
	// what let `-v` clear a file's `quiet: true` for logging while the Config
	// kept Quiet=true — silently suppressing the progress indicator for the one
	// user who explicitly asked for more output.
	verbose, err := intKey(k, "verbose")
	if err != nil {
		return nil, &app.UsageError{Err: err}
	}
	if _, quiet, err = reconcileVerbosity(flags, verbose, quiet); err != nil {
		return nil, err
	}

	policy, exitCode, err := resolvePolicy(k)
	if err != nil {
		return nil, &app.UsageError{Err: err}
	}

	cfg := &app.Config{
		Source: src,
		Target: target,

		Outputs:    outputs,
		Select:     k.String("select"),
		RulePaths:  stringsKey(k, "rules"),
		Compliance: stringsKey(k, "compliance"),
		// The CVE overlay is on by default; --no-cve, an explicit --cve=false /
		// `cve: false`, or --offline disable it. Honoring the deprecated --cve's
		// value matters: silently ignoring `cve: false` would leave a user who
		// meant "no network" making live OSV queries.
		CVE: cveFlag && !noCVE && !offline,
		// The EOL overlay reads an embedded catalog, so --offline does not
		// disable it: an offline scan can still say what stops working when.
		NoEOL: noEOL,
		// Test-scoped components are always detected and always in the native
		// document; this decides whether the table, SARIF, and the gate count them.
		IncludeTests: includeTests,

		Parallel:      parallel,
		IOBudget:      ioBudget,
		MaxFileSize:   maxFileSize,
		MinConfidence: minConfidence,

		IgnoreGlobs: stringsKey(k, "ignore"),
		CacheDir:    k.String("cache-dir"),
		NoCache:     noCache,

		CDXVersion:       k.String("cdx-version"),
		SARIFStrictKinds: sarifStrict,

		NoCachedRules:         noCachedRules,
		AutoUpdateRules:       autoUpdateRules,
		RulesSource:           k.String("rules-source"),
		InsecureSkipSignature: insecureSkipSig,

		// Remediation runs after the AIBOM is emitted; Config.Validate rejects
		// the combinations (both flags, no CVE overlay, a non-filesystem scan)
		// where it could not do what was asked.
		Fix:       doFix,
		FixAll:    doFixAll,
		FixVerify: doFixVerify,

		Policy:   policy,
		ExitCode: exitCode,

		Quiet:      quiet,
		NoProgress: noProgress,

		Offline:   offline,
		PProfAddr: k.String("pprof"),
		TraceFile: k.String("trace"),
		Stats:     stats,
		Wide:      wide,

		ImageInput:    k.String("input"),
		ImagePlatform: k.String("platform"),

		K8sNamespace:      k.String("namespace"),
		K8sAllNamespaces:  k8sAll,
		K8sManifests:      k.String("manifests"),
		K8sParallelImages: k8sParallelImages,
	}
	return cfg, nil
}

// resolveOutputs merges -o specs with the --format alias. Explicitly
// passing both on the command line is an error; otherwise the higher layer
// wins across the two spellings (an env --format beats a file output: list),
// and within one layer an output list beats the single-format alias.
func resolveOutputs(l *layers, flags *pflag.FlagSet) ([]app.OutputSpec, error) {
	k := l.k
	raw := stringsKey(k, "output")
	format := strings.TrimSpace(k.String("format"))
	outChanged := flags.Changed("output")
	fmtChanged := flags.Changed("format")

	switch {
	case outChanged && fmtChanged:
		return nil, fmt.Errorf("--format and -o/--output are mutually exclusive; use repeated -o for multi-output")
	case fmtChanged:
		raw = []string{format}
	case outChanged:
		// raw already holds the explicit -o values.
	case format != "" && l.env.Exists("format") && !l.env.Exists("output"):
		raw = []string{format} // env-provided alias beats a file-provided output list
	case format != "" && len(raw) == 0:
		raw = []string{format} // alias from file/env with no output list anywhere
	}

	return parseOutputSpecs(raw)
}

// exitCodeUnset is the --exit-code flag default: a sentinel meaning "no
// layer set it", so that an explicit 0 (report matches, never fail) is
// distinguishable from unset.
const exitCodeUnset = -1

// resolvePolicy applies the documented --exit-code/--fail-on interaction:
//
//	--fail-on alone            -> policy active, exit code defaults to 1
//	--fail-on + --exit-code N  -> policy active, exit code N (0 = report-only)
//	--exit-code N alone (N>0)  -> fail on ANY component with code N
//	--exit-code 0 alone        -> no gate (same as unset)
//	neither                    -> no gate; scan success always exits 0
func resolvePolicy(k *koanf.Koanf) (*app.Policy, int, error) {
	failOn := strings.TrimSpace(k.String("fail-on"))
	exitCode, err := intKey(k, "exit-code")
	if err != nil {
		return nil, 0, err
	}
	if exitCode != exitCodeUnset && (exitCode < 0 || exitCode > 255) {
		return nil, 0, fmt.Errorf("--exit-code must be in [0,255], got %d", exitCode)
	}

	switch {
	case failOn != "":
		p, err := app.ParsePolicy(failOn)
		if err != nil {
			return nil, 0, err
		}
		if exitCode == exitCodeUnset {
			exitCode = 1 // documented default when a policy is active
		}
		return p, exitCode, nil
	case exitCode == exitCodeUnset || exitCode == 0:
		return nil, 0, nil
	default:
		return app.MatchAny(), exitCode, nil
	}
}
