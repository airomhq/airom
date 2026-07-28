package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/eol"
	"github.com/airomhq/airom/pkg/airom"
)

// eolScanDay pins the day every test here reasons from, so a curated shutdown
// date passing in real life can never change what these assertions mean.
var eolScanDay = time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

// eolFixture is a tree referencing one retired model, one with an announced
// retirement still ahead, and one the catalog says nothing about.
func eolFixture(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"app.py": `from openai import OpenAI
c = OpenAI()
c.chat.completions.create(model="gpt-4-32k", messages=[])
c.chat.completions.create(model="gpt-4-turbo", messages=[])
c.chat.completions.create(model="gpt-4o", messages=[])
`,
	})
}

func eolByName(inv *airom.Inventory) map[string]*airom.Lifecycle {
	out := map[string]*airom.Lifecycle{}
	for _, c := range inv.Components {
		if c.Kind == airom.KindHostedLLM {
			out[c.Name] = c.EOL
		}
	}
	return out
}

func scanEOL(t *testing.T, mutate func(*Config)) *airom.Inventory {
	t.Helper()
	cfg := &Config{
		Source: SourceFS, Target: eolFixture(t),
		CacheDir: t.TempDir(), // never read the developer's real rule bundle
		Now:      eolScanDay,
	}
	if mutate != nil {
		mutate(cfg)
	}
	inv, err := Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return inv
}

// TestEOLOverlayRunsByDefault: the pipeline attaches lifecycle facts without
// any flag, and a model the catalog does not cover gets NO record — "unknown"
// is the absence of a claim, never a quiet "supported".
func TestEOLOverlayRunsByDefault(t *testing.T) {
	got := eolByName(scanEOL(t, nil))

	retired := got["gpt-4-32k"]
	if retired == nil || retired.State != airom.EOLRetired {
		t.Fatalf("gpt-4-32k should be retired, got %+v", retired)
	}
	if retired.Replacement != "gpt-4o" {
		t.Errorf("retired model should name its migration target, got %q", retired.Replacement)
	}
	if retired.DaysRemaining == nil || *retired.DaysRemaining >= 0 {
		t.Errorf("a retired model must report a negative daysRemaining, got %v", retired.DaysRemaining)
	}
	if retired.SourceURL == "" || retired.Verified == nil {
		t.Errorf("every EOL claim must be sourced and dated, got %+v", retired)
	}

	deprecated := got["gpt-4-turbo"]
	if deprecated == nil || deprecated.State != airom.EOLDeprecated {
		t.Fatalf("gpt-4-turbo should be deprecated, got %+v", deprecated)
	}
	if deprecated.DaysRemaining == nil || *deprecated.DaysRemaining <= 0 {
		t.Errorf("a live deprecation must report days still remaining, got %v", deprecated.DaysRemaining)
	}

	if lc, ok := got["gpt-4o"]; !ok {
		t.Error("gpt-4o should still be inventoried")
	} else if lc != nil {
		t.Errorf("an uncurated model must carry no lifecycle claim, got %+v", lc)
	}
}

// TestEOLWorksOffline is the property that separates this overlay from the CVE
// one: the catalog is embedded, so --offline still answers "what stops working
// and when" instead of going silent.
func TestEOLWorksOffline(t *testing.T) {
	got := eolByName(scanEOL(t, func(c *Config) { c.Offline = true }))
	if lc := got["gpt-4-32k"]; lc == nil || lc.State != airom.EOLRetired {
		t.Fatalf("EOL must survive --offline (embedded catalog), got %+v", lc)
	}
}

func TestNoEOLDisablesTheOverlay(t *testing.T) {
	for name, lc := range eolByName(scanEOL(t, func(c *Config) { c.NoEOL = true })) {
		if lc != nil {
			t.Errorf("--no-eol must attach nothing, but %s has %+v", name, lc)
		}
	}
}

// TestEOLGateEndToEnd drives the whole pipeline through the exit-code contract:
// a real scan, the real catalog, and the real policy evaluation deciding
// whether CI fails. The fixture pins gpt-4-32k (retired 2025-06-06) and
// gpt-4-turbo (shuts down 2026-10-23), scanned as of 2026-07-23.
func TestEOLGateEndToEnd(t *testing.T) {
	run := func(t *testing.T, expr string, mutate func(*Config)) error {
		t.Helper()
		var buf bytes.Buffer
		orig := stdout
		stdout = &buf
		t.Cleanup(func() { stdout = orig })

		p, err := ParsePolicy(expr)
		if err != nil {
			t.Fatalf("ParsePolicy(%q): %v", expr, err)
		}
		cfg := &Config{
			Source: SourceFS, Target: eolFixture(t), CacheDir: t.TempDir(),
			Now: eolScanDay, Policy: p, ExitCode: 1,
		}
		if mutate != nil {
			mutate(cfg)
		}
		return Run(context.Background(), cfg)
	}
	matched := func(t *testing.T, err error) bool {
		t.Helper()
		var pe *PolicyExit
		if errors.As(err, &pe) {
			return true
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return false
	}

	cases := []struct {
		expr string
		want bool
	}{
		{"eol", true},                    // gpt-4-32k is retired
		{"eol:retired", true},            // ditto
		{"eol:deprecated", true},         // threshold: retired counts
		{"eol:before:2026-01-01", true},  // the retired one is long gone
		{"eol:before:2025-01-01", false}, // nothing dies that early
		{"eol:before:2027-01-01", true},  // gpt-4-turbo dies 2026-10-23
		{"hosted-llm&eol:retired", true}, // both terms on one component
		{"vector-db&eol:retired", false}, // no single component is both
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			if got := matched(t, run(t, tc.expr, nil)); got != tc.want {
				t.Errorf("--fail-on %q matched = %v, want %v", tc.expr, got, tc.want)
			}
		})
	}

	// The gate survives --offline: this overlay reads an embedded catalog, so
	// an airgapped CI run can still block on a model that stopped answering.
	t.Run("offline still gates", func(t *testing.T) {
		if !matched(t, run(t, "eol:retired", func(c *Config) { c.Offline = true })) {
			t.Error("--offline must not silence the lifecycle gate")
		}
	})

	// And gating on an overlay that was turned off is a loud config error, not
	// a gate that quietly always passes.
	t.Run("--no-eol is a usage error", func(t *testing.T) {
		err := run(t, "eol:retired", func(c *Config) { c.NoEOL = true })
		if err == nil || !strings.Contains(err.Error(), "lifecycle overlay is disabled") {
			t.Errorf("want a clear config error, got %v", err)
		}
	})

	// The gate must fail CLOSED when the overlay could not be evaluated at all.
	// A catalog that fails to load yields no findings, so every eol term would
	// return false and the build would go green on an unevaluated gate — the
	// one outcome that must never be a lie. Mirrors the CVE gate's behavior.
	t.Run("unloadable catalog fails the gate closed", func(t *testing.T) {
		// A shutdown boundary is irrelevant here; what matters is that the
		// scan refuses rather than reporting a clean result it cannot back.
		err := runWithBrokenCatalog(t, "eol:retired")
		if err == nil {
			t.Fatal("an unevaluated eol gate must fail the scan, not pass it")
		}
		if !strings.Contains(err.Error(), "cannot be evaluated") {
			t.Errorf("error should say the gate could not be evaluated, got %v", err)
		}
		var pe *PolicyExit
		if errors.As(err, &pe) {
			t.Error("this is a scan failure, not a policy match")
		}
	})
}

// runWithBrokenCatalog runs a scan whose lifecycle catalog cannot be loaded.
func runWithBrokenCatalog(t *testing.T, expr string) error {
	t.Helper()
	orig := loadEmbeddedEOLCatalog
	loadEmbeddedEOLCatalog = func() (*eol.Catalog, error) { return nil, errors.New("catalog unreadable") }
	t.Cleanup(func() { loadEmbeddedEOLCatalog = orig })

	var buf bytes.Buffer
	so := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = so })

	p, err := ParsePolicy(expr)
	if err != nil {
		t.Fatal(err)
	}
	return Run(context.Background(), &Config{
		Source: SourceFS, Target: eolFixture(t), CacheDir: t.TempDir(),
		Now: eolScanDay, Policy: p, ExitCode: 1,
	})
}

// TestBrokenCatalogWithoutAGateOnlyWarns: with no eol gate active, an
// unloadable catalog costs the overlay, never the AIBOM.
func TestBrokenCatalogWithoutAGateOnlyWarns(t *testing.T) {
	orig := loadEmbeddedEOLCatalog
	loadEmbeddedEOLCatalog = func() (*eol.Catalog, error) { return nil, errors.New("catalog unreadable") }
	t.Cleanup(func() { loadEmbeddedEOLCatalog = orig })

	inv := scanEOL(t, nil)
	var found bool
	for _, w := range inv.Stats.Warnings {
		if strings.Contains(w, "lifecycle catalog unavailable") {
			found = true
		}
	}
	if !found {
		t.Errorf("a degraded overlay must warn, got %v", inv.Stats.Warnings)
	}
	for _, c := range inv.Components {
		if c.EOL != nil {
			t.Errorf("no lifecycle claims should survive a failed load, got %+v", c.EOL)
		}
	}
}

// writeBundle stages a cache holding a signed-bundle layout: rule packs at the
// root (where tools/bundle tars them) plus the lifecycle catalogs under eol/.
func writeBundle(t *testing.T, catalog string) string {
	t.Helper()
	cacheDir := t.TempDir()
	const version = "v9.9.9"
	root := filepath.Join(cacheDir, "rules", version)
	for _, d := range []string{filepath.Join(root, "eol"), filepath.Join(root, "models")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A real bundle carries rule packs beside the catalog. Without one here the
	// test could not tell "the catalog was ignored" from "the ruleset broke".
	pack := `pack: openai
version: 1
rules:
  - id: openai/model-literal
    kind: hosted-llm
    provider: openai
    languages: [python]
    keywords: ["gpt-"]
    pattern: 'model\s*[:=]\s*["''](?P<model>gpt-[\w.\-]+)["'']'
    claim: { name: "${model}" }
    confidence: 0.85
`
	if err := os.WriteFile(filepath.Join(root, "models", "openai.yaml"), []byte(pack), 0o644); err != nil {
		t.Fatal(err)
	}
	// A second provider, so a test can show that a bundle catalog covering only
	// ONE provider leaves the other's embedded records intact.
	anthropicPack := "pack: anthropic\nversion: 1\nrules:\n" +
		"  - id: anthropic/model-literal\n" +
		"    kind: hosted-llm\n" +
		"    provider: anthropic\n" +
		"    languages: [python]\n" +
		"    keywords: [\"claude-\"]\n" +
		"    pattern: 'model\\s*[:=]\\s*\"(?P<model>claude-[\\w.\\-]+)\"'\n" +
		"    claim: { name: \"${model}\" }\n" +
		"    confidence: 0.85\n"
	if err := os.WriteFile(filepath.Join(root, "models", "anthropic.yaml"), []byte(anthropicPack), 0o644); err != nil {
		t.Fatal(err)
	}
	if catalog != "" {
		if err := os.WriteFile(filepath.Join(root, "eol", "openai.yaml"), []byte(catalog), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "rules", "current.json"),
		[]byte(`{"version":"`+version+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return cacheDir
}

// bundleOpenAICatalog says something the EMBEDDED catalog does not (gpt-4o is
// uncurated there), so any claim about gpt-4o can only have come from here.
const bundleOpenAICatalog = `provider: openai
source: https://developers.openai.com/api/docs/deprecations
verified: 2026-07-23
models:
  - id: gpt-4o
    state: deprecated
    announced: 2026-07-01
    shutdown: 2027-01-01
    replacement: gpt-5.6-sol
`

// TestBundleCatalogOverridesEmbedded is the Model B payoff: retirement dates
// change on a provider's calendar, not on AIROM's release schedule, so a
// verified bundle can carry a fresher catalog than the binary shipped with —
// and `airom rules update` becomes the refresh lever instead of an upgrade.
func TestBundleCatalogOverridesEmbedded(t *testing.T) {
	cacheDir := writeBundle(t, bundleOpenAICatalog)

	inv := scanEOL(t, func(c *Config) { c.CacheDir = cacheDir })
	got := eolByName(inv)
	if lc := got["gpt-4o"]; lc == nil || lc.State != airom.EOLDeprecated || lc.Replacement != "gpt-5.6-sol" {
		t.Fatalf("the bundle catalog should have supplied gpt-4o, got %+v", lc)
	}

	// Carrying a catalog must NOT cost the bundle its rules. The rule walk and
	// the catalog share the bundle root, and a catalog is not a parseable rule
	// pack — so publishing one used to fail the whole ruleset and silently drop
	// the scan back to the built-in packs, turning off the channel it shipped in.
	if inv.Tool.RulesVersion != "v9.9.9" {
		t.Errorf("rulesVersion = %q, want the bundle version: a catalog must not break the rule layer",
			inv.Tool.RulesVersion)
	}

	// --no-cached-rules pins the scan to the built-in catalog, which says
	// nothing about gpt-4o — the same escape hatch the rule packs have.
	embedded := eolByName(scanEOL(t, func(c *Config) { c.CacheDir = cacheDir; c.NoCachedRules = true }))
	if lc := embedded["gpt-4o"]; lc != nil {
		t.Errorf("--no-cached-rules must fall back to the embedded catalog, got %+v", lc)
	}
	if lc := embedded["gpt-4-32k"]; lc == nil || lc.State != airom.EOLRetired {
		t.Errorf("embedded fallback should still resolve gpt-4-32k, got %+v", lc)
	}
}

// TestEOLCatalogProvenanceIsRecorded: a lifecycle claim is only as good as the
// catalog and date behind it. "gpt-4o retires 2026-11-01" from an eight-month-old
// embedded catalog and the same line from yesterday's bundle are not equally
// trustworthy, and a reader holding only the artifact cannot tell them apart
// unless the document says which layer answered.
func TestEOLCatalogProvenanceIsRecorded(t *testing.T) {
	cacheDir := writeBundle(t, bundleOpenAICatalog)

	if got := scanEOL(t, func(c *Config) { c.CacheDir = cacheDir }).Tool.EOLCatalog; got != "builtin+v9.9.9" {
		t.Errorf("eolCatalog = %q, want builtin+v9.9.9 — after a per-provider merge BOTH layers answer", got)
	}
	if got := scanEOL(t, func(c *Config) { c.CacheDir = cacheDir; c.NoCachedRules = true }).Tool.EOLCatalog; got != "builtin" {
		t.Errorf("eolCatalog = %q, want builtin when the scan is pinned to the embedded catalog", got)
	}
	// A rejected bundle catalog did not contribute, so claiming it did would be
	// the one lie that matters here: the artifact says builtin, and the warning
	// says why.
	broken := writeBundle(t, "provider: openai\nverified: 2026-07-23\nmodels:\n  - {id: m, state: supported}\n")
	if got := scanEOL(t, func(c *Config) { c.CacheDir = broken }).Tool.EOLCatalog; got != "builtin" {
		t.Errorf("eolCatalog = %q, want builtin: a catalog that failed to load produced nothing", got)
	}
	// No overlay, no claims, no provenance to state.
	if got := scanEOL(t, func(c *Config) { c.CacheDir = cacheDir; c.NoEOL = true }).Tool.EOLCatalog; got != "" {
		t.Errorf("eolCatalog = %q, want empty when --no-eol turned the overlay off", got)
	}
}

// TestBundleCatalogOverlaysPerProvider: publishing is incremental. A bundle
// shipping only eol/openai.yaml says "here is newer OpenAI data", NOT "Anthropic
// no longer has retirement dates" — so untouched providers keep the embedded
// records instead of vanishing and flipping a --fail-on eol gate green.
func TestBundleCatalogOverlaysPerProvider(t *testing.T) {
	cacheDir := writeBundle(t, bundleOpenAICatalog)
	target := writeTree(t, map[string]string{
		"app.py": `import anthropic
c = anthropic.Anthropic()
c.messages.create(model="claude-1.0", max_tokens=1, messages=[])
`,
	})
	inv, err := Scan(context.Background(), &Config{
		Source: SourceFS, Target: target, CacheDir: cacheDir, Now: eolScanDay,
	})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range inv.Components {
		if c.Name == "claude-1.0" {
			found = true
			if c.EOL == nil || c.EOL.State != airom.EOLRetired {
				t.Errorf("a provider the bundle is silent about must keep its embedded records, got %+v", c.EOL)
			}
		}
	}
	if !found {
		t.Fatal("claude-1.0 was not detected")
	}
}

// TestBrokenBundleCatalogWarnsInTheArtifact: stderr is routinely discarded in
// CI and the BOM is the record, so a rejected catalog has to say so there.
func TestBrokenBundleCatalogWarnsInTheArtifact(t *testing.T) {
	// Valid YAML, invalid per the honesty contract: no source URL.
	cacheDir := writeBundle(t, `provider: openai
verified: 2026-07-23
models:
  - {id: m, state: supported}
`)
	inv := scanEOL(t, func(c *Config) { c.CacheDir = cacheDir })

	var found bool
	for _, w := range inv.Stats.Warnings {
		if strings.Contains(w, "could not be loaded and was ignored") {
			found = true
		}
	}
	if !found {
		t.Errorf("a rejected bundle catalog must warn in the artifact, got %v", inv.Stats.Warnings)
	}
	// And the scan degrades to the embedded catalog rather than losing the overlay.
	if lc := eolByName(inv)["gpt-4-32k"]; lc == nil || lc.State != airom.EOLRetired {
		t.Errorf("a bad publish must not be worse than an old binary, got %+v", lc)
	}
}

// TestWarningsSurviveTheStatsReset is the honesty channel's contract. Without
// --stats the emitter drops the volatile stats block, and warnings used to go
// with it — so a scan whose advisory database was unreachable or whose
// lifecycle catalog failed to load produced output byte-identical to a clean
// one. Under -q the log copy is suppressed too, which left no trace anywhere.
func TestWarningsSurviveTheStatsReset(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "aibom.json")
	inv := &airom.Inventory{
		SchemaVersion: "1",
		Tool:          airom.ToolInfo{Name: "airom", Version: "test"},
		Serial:        "urn:uuid:00000000-0000-4000-8000-000000000000",
		Timestamp:     eolScanDay,
		Source:        airom.SourceInfo{Kind: "dir", Target: "."},
		Stats: airom.ScanStats{
			FilesWalked: 1, FilesProcessed: 1,
			Duration: 12345, // volatile: must be dropped
			Warnings: []string{"eol: model lifecycle catalog unavailable"},
		},
	}
	cfg := &Config{
		Source: SourceFS, Target: ".", CacheDir: dir,
		Outputs: []OutputSpec{{Format: FormatJSON, Path: out}},
		Stats:   false, // the default: stats block is reset
	}
	cfg.ApplyDefaults()
	if err := emit(context.Background(), inv, cfg); err != nil {
		t.Fatalf("emit: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Stats struct {
			Warnings []string `json:"warnings"`
			Duration int64    `json:"duration"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Stats.Warnings) != 1 {
		t.Errorf("warnings must survive the stats reset, got %v", got.Stats.Warnings)
	}
	if got.Stats.Duration != 0 {
		t.Errorf("the volatile duration must still be dropped, got %d", got.Stats.Duration)
	}
}

// TestEOLDerivesFromTheScanClock pins the determinism seam: the overlay's
// answer is a function of the scan day, so pinning that day pins the output —
// which is what keeps the golden suite from rotting as real dates pass.
func TestEOLDerivesFromTheScanClock(t *testing.T) {
	// gpt-4-turbo's shutdown is 2026-10-23.
	before := eolByName(scanEOL(t, func(c *Config) { c.Now = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC) }))
	after := eolByName(scanEOL(t, func(c *Config) { c.Now = time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) }))

	if lc := before["gpt-4-turbo"]; lc == nil || lc.State != airom.EOLDeprecated {
		t.Errorf("the day before shutdown it is still deprecated, got %+v", lc)
	}
	if lc := after["gpt-4-turbo"]; lc == nil || lc.State != airom.EOLRetired {
		t.Errorf("on the shutdown day it is retired, got %+v", lc)
	}

	// The BOM timestamp and the EOL evaluation share one clock, so a BOM can
	// never be dated one month and reason about another.
	inv := scanEOL(t, func(c *Config) { c.Now = eolScanDay })
	if !inv.Timestamp.Equal(eolScanDay) {
		t.Errorf("Config.Now must stamp the BOM too, got %s", inv.Timestamp)
	}
}
