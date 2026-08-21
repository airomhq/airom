package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"

	"github.com/airomhq/airom/internal/app"
)

// addGlobalFlags registers the global scan flags from docs/cli.md ("Global
// flags") on the root's persistent flag set. Flag defaults double as the
// bottom layer of the configuration precedence (flags > env > file >
// defaults): the posflag provider only overrides file/env values when a
// flag was explicitly set.
func addGlobalFlags(fs *pflag.FlagSet) {
	fs.StringArrayP("output", "o", nil,
		fmt.Sprintf("output as fmt[=path]; repeatable; formats: %s (default table to stdout)",
			strings.Join(app.Formats(), ", ")))
	fs.String("format", "", "single-format alias for -o (mutually exclusive with -o)")
	fs.String("select", "", `detector selection expression, e.g. "rules,+modelfile/gguf,-dataset/file"`)
	fs.StringArray("rules", nil, "overlay rule pack file; repeatable; merged by rule ID")
	fs.StringArray("compliance", nil,
		fmt.Sprintf("map the AIBOM onto a governance framework; repeatable; frameworks: %s",
			strings.Join(app.ComplianceFrameworks(), ", ")))
	// The CVE overlay is on by default. --no-cve (or --offline) turns it off.
	// --cve is kept for commands written against v0.1.6 (when it was opt-in): it
	// defaults true, so it is normally redundant, but an explicit --cve=false (or
	// `cve: false` in a config file) is still honored — silently ignoring it would
	// leave a user who meant "no network" making live queries.
	fs.Bool("cve", true, "deprecated: the CVE overlay is on by default; use --no-cve to disable")
	_ = fs.MarkDeprecated("cve", "the CVE overlay is on by default now; use --no-cve to disable it")
	fs.Bool("no-cve", false, "disable the OSV.dev CVE overlay (it is on by default; also implied by --offline)")
	// The EOL overlay reads an embedded catalog, so unlike --cve it needs no
	// network and stays on under --offline.
	fs.Bool("no-eol", false, "disable the hosted-model end-of-life overlay (it is on by default and works offline)")
	// Remediation. --fix is interactive by design: it edits files in the user's
	// working tree, and the one place a scanner must not act on its own guess is
	// the place where it writes. --fix-all is the same plan applied without the
	// table, for a terminal that cannot host one.
	fs.Bool("fix", false, "after the scan, open an interactive advisory table and rewrite the manifest pins you choose (needs a terminal)")
	fs.Bool("fix-all", false, "rewrite every vulnerable manifest pin to its fixed version without prompting (implies no table)")
	fs.Bool("fix-verify", false, "after fixing, run the ecosystem's resolver in dry-run mode to confirm the new pins still resolve (installs nothing)")
	fs.Bool("include-tests", false, "count AI found only in test scaffolding (testdata/, *_test.go, tests/, spec/) — hidden by default")
	fs.Int("parallel", 0, "worker count (default: GOMAXPROCS)")
	fs.String("io-budget", formatSize(app.DefaultIOBudget), "byte-weighted I/O semaphore budget (k/m/g suffixes)")
	fs.String("max-file-size", formatSize(app.DefaultMaxFileSize), "full-content read cap for text detectors (k/m/g suffixes)")
	fs.Float64("min-confidence", 0, "presentation-layer confidence filter, 0-1")
	fs.StringArray("ignore", nil, "additional ignore glob; repeatable; applied on top of .gitignore/.airomignore")
	// The two-tier cache (internal/cache) is not implemented yet, so these
	// configure nothing. Say so rather than describing behavior the binary does
	// not have — `airom clean` does still use --cache-dir.
	// No backquotes in usage strings: pflag reads backquoted text as the flag's
	// placeholder name, so "`airom clean`" renders as "--cache-dir airom clean".
	fs.String("cache-dir", "", "scan cache location (default: <user cache dir>/airom); used by 'airom clean' — caching itself is not implemented yet")
	fs.Bool("no-cache", false, "disable cache reads and writes (no-op: caching is not implemented yet, every scan is cold)")
	fs.String("cdx-version", app.DefaultCDXVersion, "CycloneDX spec version: 1.6 or 1.7")
	fs.Bool("sarif-strict-kinds", false, `emit spec-pure kind:"informational" instead of level:"note"`)
	fs.Int("exit-code", exitCodeUnset, "exit status when --fail-on matches (default 1 when a policy is active; 0 reports matches without failing)")
	// exitCodeUnset is a sentinel, not a default. pflag renders any non-zero
	// default as "(default -1)", which is not a valid exit status and flatly
	// contradicts the sentence above it. DefValue is display-only — parsing and
	// Changed() read the Value — so clearing it to the type's zero suppresses the
	// line and leaves the real defaults where they are already stated: in the
	// help text.
	fs.Lookup("exit-code").DefValue = "0"
	fs.String("fail-on", "", `CI policy expression, e.g. "hosted-llm&confidence>=0.9" (see docs/cli.md)`)
	fs.Bool("offline", false, "assert no network access for the entire run")
	fs.String("pprof", "", "serve net/http/pprof (bare flag: localhost:6060; custom addr must be attached: --pprof=host:port)")
	fs.Lookup("pprof").NoOptDefVal = "localhost:6060"
	fs.String("trace", "", "write a Go execution trace to file")
	fs.Bool("no-progress", false, "disable the scan progress indicator (auto-off when stderr is not a terminal)")
	fs.Bool("stats", false, "emit the full ScanStats block in the output")
	fs.Bool("wide", false, "table: expand every file:line occurrence under each component")
	fs.Bool("no-cached-rules", false, "ignore any fetched rule bundle; scan with the built-in packs")
	fs.Bool("auto-update-rules", true, "check airom-rules for a newer bundle before scanning (at most once a day; skipped offline and in CI)")
	fs.CountP("verbose", "v", "increase log verbosity (repeatable; -vv adds source locations)")
	fs.BoolP("quiet", "q", false, "errors only")
}
