package eol

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/airomhq/airom/pkg/airom"
)

const bundleCatalog = `provider: openai
source: https://developers.openai.com/api/docs/deprecations
verified: 2026-07-23
models:
  - id: gpt-9
    state: deprecated
    announced: 2026-07-01
    shutdown: 2027-01-01
    replacement: gpt-10
`

// TestLoadBundleReadsTheChannelCatalog: retirement dates change on a provider's
// calendar, not on AIROM's release schedule, so the signed bundle can carry a
// fresher catalog than the binary was built with.
func TestLoadBundleReadsTheChannelCatalog(t *testing.T) {
	bundle := fstest.MapFS{
		BundleDir + "/openai.yaml": &fstest.MapFile{Data: []byte(bundleCatalog)},
		// Rule packs share the bundle and must be ignored here.
		"rules/frameworks/langchain.yaml": &fstest.MapFile{Data: []byte("pack: langchain\nversion: 1\nrules: []\n")},
	}
	c, ok, err := LoadBundle(bundle, scanDay)
	if err != nil || !ok {
		t.Fatalf("LoadBundle = ok:%v err:%v, want a catalog", ok, err)
	}
	if c.Source() != SourceBundle {
		t.Errorf("Source() = %q, want %q — the staleness advice depends on it", c.Source(), SourceBundle)
	}
	lc := c.Lookup("openai", "gpt-9", scanDay)
	if lc == nil || lc.Replacement != "gpt-10" {
		t.Fatalf("bundle record not loaded: %+v", lc)
	}
}

// TestLoadBundleWithoutACatalogIsNotAnError: a bundle published before this
// feature simply carries no eol/ dir. The caller must fall back to the embedded
// catalog rather than treat an older channel as a failure.
func TestLoadBundleWithoutACatalogIsNotAnError(t *testing.T) {
	for name, bundle := range map[string]fstest.MapFS{
		"rules only": {"rules/models/openai.yaml": &fstest.MapFile{Data: []byte("pack: openai\nversion: 1\nrules: []\n")}},
		"empty":      {},
	} {
		c, ok, err := LoadBundle(bundle, scanDay)
		if err != nil || ok || c != nil {
			t.Errorf("%s: LoadBundle = (%v, %v, %v), want (nil, false, nil)", name, c, ok, err)
		}
	}
	if _, ok, err := LoadBundle(nil, scanDay); ok || err != nil {
		t.Error("a nil bundle must be a clean miss")
	}
}

// TestLoadBundleReportsABrokenCatalog: a bundle that HAS a catalog and cannot
// parse it is a publishing failure worth reporting, not a silent miss — the
// caller degrades to the embedded one, but it must know why.
func TestLoadBundleReportsABrokenCatalog(t *testing.T) {
	bundle := fstest.MapFS{
		BundleDir + "/openai.yaml": &fstest.MapFile{
			Data: []byte("provider: openai\nverified: 2026-07-23\nmodels:\n  - {id: m, state: supported}\n"), // no source URL
		},
	}
	c, ok, err := LoadBundle(bundle, scanDay)
	if err == nil {
		t.Fatal("a malformed bundle catalog must report an error")
	}
	if !ok {
		t.Error("ok must be true: the bundle carried a catalog, it was just broken")
	}
	if c != nil {
		t.Error("no catalog should be returned")
	}
	if !strings.Contains(err.Error(), "source URL is required") {
		t.Errorf("error should name the contract violation, got %v", err)
	}
}

// TestStalenessAdviceNamesTheRightLever: telling a user to run
// `airom rules update` against an embedded catalog sends them in a circle
// (command succeeds, warning unchanged), and telling them to upgrade the binary
// when the channel already has fresher data sends them the long way round.
func TestStalenessAdviceNamesTheRightLever(t *testing.T) {
	old := "provider: p\nsource: https://x\nverified: 2026-01-01\nmodels:\n  - {id: m, state: supported}\n"

	embedded, err := loadYAML(t, old)
	if err != nil {
		t.Fatal(err)
	}
	if w := embedded.StalenessWarning(scanDay); !strings.Contains(w, "upgrade airom") {
		t.Errorf("an embedded catalog must advise upgrading, got %q", w)
	}

	fromBundle, ok, err := LoadBundle(fstest.MapFS{
		BundleDir + "/p.yaml": &fstest.MapFile{Data: []byte(old)},
	}, scanDay)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if w := fromBundle.StalenessWarning(scanDay); !strings.Contains(w, "airom rules update") {
		t.Errorf("a bundle catalog must advise refreshing the channel, got %q", w)
	}
}

// TestOverlayIsPerProvider: publishing is incremental. A bundle covering one
// provider must not delete another's records — that would silently remove
// coverage and flip a --fail-on eol gate green with nothing to explain why.
func TestOverlayIsPerProvider(t *testing.T) {
	base, err := loadFS(fstest.MapFS{
		"c/openai.yaml":    &fstest.MapFile{Data: []byte("provider: openai\nsource: https://o\nverified: 2026-07-01\nmodels:\n  - {id: old-gpt, state: supported}\n")},
		"c/anthropic.yaml": &fstest.MapFile{Data: []byte("provider: anthropic\nsource: https://a\nverified: 2026-07-01\nmodels:\n  - {id: claude-1.0, state: deprecated, announced: 2024-09-04, shutdown: 2024-11-06}\n")},
	}, "c", scanDay)
	if err != nil {
		t.Fatal(err)
	}
	overlay, _, err := LoadBundle(fstest.MapFS{
		BundleDir + "/openai.yaml": &fstest.MapFile{Data: []byte(bundleCatalog)},
	}, scanDay)
	if err != nil {
		t.Fatal(err)
	}

	merged := Overlay(base, overlay)
	// The overlay's provider is fully re-stated: its new record is present…
	if lc := merged.Lookup("openai", "gpt-9", scanDay); lc == nil {
		t.Error("the overlay's own record must win")
	}
	// …and a record it dropped IS dropped, because a provider file is the unit
	// a maintainer edits and re-verifies.
	if lc := merged.Lookup("openai", "old-gpt", scanDay); lc != nil {
		t.Error("within a replaced provider, records the overlay omits are gone")
	}
	// The untouched provider survives intact — the whole point.
	if lc := merged.Lookup("anthropic", "claude-1.0", scanDay); lc == nil || lc.State != airom.EOLRetired {
		t.Errorf("a provider the overlay is silent about must be preserved, got %+v", lc)
	}
	if merged.Source() != SourceBundle {
		t.Errorf("Source() = %q, want bundle", merged.Source())
	}

	// Nil-safety on both sides.
	if Overlay(base, nil) != base || Overlay(nil, overlay) != overlay {
		t.Error("Overlay must be nil-safe")
	}
}

// TestLoadBundleFindsNestedCatalogs: the rule walk skips the whole eol/ tree, so
// a nested catalog must be picked up here or it would be honored by nothing.
func TestLoadBundleFindsNestedCatalogs(t *testing.T) {
	c, ok, err := LoadBundle(fstest.MapFS{
		BundleDir + "/providers/openai.yaml": &fstest.MapFile{Data: []byte(bundleCatalog)},
	}, scanDay)
	if err != nil || !ok {
		t.Fatalf("nested catalog not loaded: ok=%v err=%v", ok, err)
	}
	if c.Lookup("openai", "gpt-9", scanDay) == nil {
		t.Error("a nested catalog's records must resolve")
	}
}

func TestIsCatalogFile(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"catalog", bundleCatalog, true},
		{"rule pack", "pack: openai\nversion: 1\nrules:\n  - {id: a/b, kind: hosted-llm}\n", false},
		{"empty", "", false},
		// The likeliest publishing mistakes are catalog-SHAPED but invalid. They
		// must reach the EOL validator so the error names the right contract,
		// not the rule-pack one plus a --rules flag nobody passed.
		{"catalog missing provider", "source: https://x\nverified: 2026-07-23\nmodels:\n  - {id: m, state: supported}\n", true},
		{"catalog missing models", "provider: openai\nsource: https://x\nverified: 2026-07-23\n", true},
		{"not yaml", "\x00\x01binary", false},
		// A file with both shapes is ambiguous; treat it as a pack so the
		// stricter rule-engine validator gets to reject it.
		{"ambiguous", "provider: p\nmodels: [x]\npack: p\nrules: [y]\n", false},
	}
	for _, tc := range cases {
		if got := IsCatalogFile([]byte(tc.body)); got != tc.want {
			t.Errorf("IsCatalogFile(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestLintFile(t *testing.T) {
	provider, models, err := LintFile("x.yaml", []byte(bundleCatalog), scanDay)
	if err != nil {
		t.Fatalf("a valid catalog must lint clean: %v", err)
	}
	if provider != "openai" || models != 1 {
		t.Errorf("LintFile = (%q, %d), want (openai, 1)", provider, models)
	}
	// The lint applies the SAME contract the loader does — that is the point:
	// a maintainer catches a bad transcription before it reaches every scan.
	if _, _, err := LintFile("x.yaml", []byte("provider: p\nmodels:\n  - {id: m, state: supported}\n"), scanDay); err == nil {
		t.Error("lint must reject a catalog with no source URL")
	}
}
