package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Roro1727/airom/internal/app"
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
	fs.Int("parallel", 0, "worker count (default: GOMAXPROCS)")
	fs.String("io-budget", formatSize(app.DefaultIOBudget), "byte-weighted I/O semaphore budget (k/m/g suffixes)")
	fs.String("max-file-size", formatSize(app.DefaultMaxFileSize), "full-content read cap for text detectors (k/m/g suffixes)")
	fs.Float64("min-confidence", 0, "presentation-layer confidence filter, 0-1")
	fs.StringArray("ignore", nil, "additional ignore glob; repeatable; applied on top of .gitignore/.airomignore")
	fs.String("cache-dir", "", "scan cache location (default: <user cache dir>/airom)")
	fs.Bool("no-cache", false, "disable cache reads and writes for this run")
	fs.String("cdx-version", app.DefaultCDXVersion, "CycloneDX spec version: 1.6 or 1.7")
	fs.Bool("sarif-strict-kinds", false, `emit spec-pure kind:"informational" instead of level:"note"`)
	fs.Int("exit-code", exitCodeUnset, "exit status when --fail-on matches (default 1 when a policy is active; 0 reports matches without failing)")
	fs.String("fail-on", "", `CI policy expression, e.g. "hosted-llm&confidence>=0.9" (see docs/cli.md)`)
	fs.Bool("offline", false, "assert no network access for the entire run")
	fs.String("pprof", "", "serve net/http/pprof (bare flag: localhost:6060; custom addr must be attached: --pprof=host:port)")
	fs.Lookup("pprof").NoOptDefVal = "localhost:6060"
	fs.String("trace", "", "write a Go execution trace to file")
	fs.Bool("stats", false, "emit the full ScanStats block in the output")
	fs.CountP("verbose", "v", "increase log verbosity (repeatable; -vv adds source locations)")
	fs.BoolP("quiet", "q", false, "errors only")
}
