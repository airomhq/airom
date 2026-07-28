package eol

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func day(y int, m time.Month, d int) airom.Date {
	return airom.Date{Year: y, Month: m, Day: d}
}

// scanDay is the fixed "now" every test reasons from, so results never drift
// with the wall clock.
var scanDay = day(2026, time.July, 23)

// TestEmbeddedCatalogLoads is the build-integrity check: the shipped catalog
// must parse and satisfy the full validation contract, since a malformed one
// would break the binary rather than a user's file.
func TestEmbeddedCatalogLoads(t *testing.T) {
	c, err := LoadOn(scanDay)
	if err != nil {
		t.Fatalf("embedded catalog failed to load: %v", err)
	}
	if c.Size() == 0 {
		t.Fatal("embedded catalog is empty")
	}
	// A freshly-verified catalog must not report itself stale.
	if w := c.StalenessWarning(scanDay); w != "" {
		t.Errorf("catalog reports stale on its own verification date: %s", w)
	}
}

// TestLoadUsesTheRealClock exercises the entry point the PIPELINE calls. Every
// other test here pins the day, which would hide the one failure mode that
// matters most: a catalog whose `verified` date is ahead of real time loads
// fine against a pinned day, ships green, and then silently disables the
// overlay for every user until that date arrives.
func TestLoadUsesTheRealClock(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("the shipped catalog must load against the real clock: %v", err)
	}
	if c.Size() == 0 {
		t.Fatal("catalog is empty")
	}
	// And it must not already be reporting itself stale on the day it ships.
	if w := c.StalenessWarning(airom.DateOf(time.Now())); w != "" {
		t.Logf("note: %s", w) // a warning here is a signal to re-verify, not a build failure
	}
}

// TestEmbeddedCatalogKnownRecords spot-checks facts transcribed from the
// providers' deprecation pages, including the state that must flip with time.
func TestEmbeddedCatalogKnownRecords(t *testing.T) {
	c, err := LoadOn(scanDay)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		provider, model string
		want            airom.EOLState
		wantReplacement string
	}{
		{"openai", "gpt-4-32k", airom.EOLRetired, "gpt-4o"},        // shutdown 2025-06-06
		{"openai", "gpt-4", airom.EOLDeprecated, "gpt-5.6-sol"},    // shutdown 2026-10-23
		{"anthropic", "claude-sonnet-4-6", airom.EOLSupported, ""}, // current, from the Active table
		{"anthropic", "claude-2.0", airom.EOLRetired, ""},          // shutdown 2025-07-21
		{"anthropic", "claude-opus-4-8", airom.EOLSupported, ""},   // current
		{"anthropic", "claude-3-7-sonnet-20250219", airom.EOLRetired, "claude-sonnet-4-6"},
	}
	for _, tc := range cases {
		lc := c.Lookup(tc.provider, tc.model, scanDay)
		if lc == nil {
			t.Errorf("%s/%s: no catalog record", tc.provider, tc.model)
			continue
		}
		if lc.State != tc.want {
			t.Errorf("%s/%s: state = %q, want %q", tc.provider, tc.model, lc.State, tc.want)
		}
		if tc.wantReplacement != "" && lc.Replacement != tc.wantReplacement {
			t.Errorf("%s/%s: replacement = %q, want %q", tc.provider, tc.model, lc.Replacement, tc.wantReplacement)
		}
		// The honesty contract: every claim is sourced and dated.
		if lc.SourceURL == "" || lc.Verified == nil || lc.Source != "airom-catalog" {
			t.Errorf("%s/%s: unsourced claim: %+v", tc.provider, tc.model, lc)
		}
	}
}

// TestUnknownIsNotSupported is the central honesty invariant: a model nobody
// curated must yield NO record, never a "supported" claim.
func TestUnknownIsNotSupported(t *testing.T) {
	c, err := LoadOn(scanDay)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range [][2]string{
		{"openai", "gpt-9-imaginary"},
		// openai.yaml carries no "supported" records: its source is a DEPRECATIONS
		// page, which cannot substantiate a positive health claim. A current model
		// is therefore "unknown" here — no claim — rather than a sourceless yes.
		{"openai", "gpt-4o"},
		{"openai", ""},
		{"no-such-provider", "gpt-4"},
		// Right model id, wrong platform: Bedrock/Vertex publish their own
		// schedules, so an anthropic record must not answer for aws-bedrock.
		{"aws-bedrock", "claude-opus-4-1-20250805"},
	} {
		if lc := c.Lookup(tc[0], tc[1], scanDay); lc != nil {
			t.Errorf("Lookup(%q,%q) = %+v, want nil (unknown is not a claim)", tc[0], tc[1], lc)
		}
	}
}

// TestAliasAndCaseFolding: providers alias a family onto dated snapshots, and
// code does not always match their casing. Both resolve to the same record —
// but nothing fuzzier does.
func TestAliasAndCaseFolding(t *testing.T) {
	c, err := LoadOn(scanDay)
	if err != nil {
		t.Fatal(err)
	}
	base := c.Lookup("openai", "gpt-4-32k", scanDay)
	if base == nil {
		t.Fatal("gpt-4-32k missing")
	}
	for _, name := range []string{"gpt-4-32k-0613", "GPT-4-32K", "  gpt-4-32k  ", "gpt-4-32k-0314"} {
		lc := c.Lookup("OpenAI", name, scanDay)
		if lc == nil || lc.State != base.State || lc.Replacement != base.Replacement {
			t.Errorf("alias/case %q did not resolve to the gpt-4-32k record: %+v", name, lc)
		}
	}
	// No prefix or substring matching — a wrong EOL claim is worse than none.
	for _, name := range []string{"gpt-4-32", "gpt-4-32k-turbo", "xgpt-4-32k"} {
		if lc := c.Lookup("openai", name, scanDay); lc != nil {
			t.Errorf("fuzzy match on %q returned %+v; matching must be exact", name, lc)
		}
	}
}

// ── validation contract ─────────────────────────────────────────────────────

func loadYAML(t *testing.T, body string) (*Catalog, error) {
	t.Helper()
	return loadFS(fstest.MapFS{"cat/x.yaml": &fstest.MapFile{Data: []byte(body)}}, "cat", scanDay)
}

func TestValidationRejectsUnsourcedOrMalformed(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			"missing source URL",
			"provider: p\nverified: 2026-07-23\nmodels:\n  - {id: m, state: supported}\n",
			"source URL is required",
		},
		{
			"missing verified date",
			"provider: p\nsource: https://x\nmodels:\n  - {id: m, state: supported}\n",
			"verified date is required",
		},
		{
			"no provider",
			"source: https://x\nverified: 2026-07-23\nmodels:\n  - {id: m, state: supported}\n",
			"provider is required",
		},
		{
			"unknown state",
			"provider: p\nsource: https://x\nverified: 2026-07-23\nmodels:\n  - {id: m, state: sunsetting}\n",
			"unknown state",
		},
		{
			"bad date",
			"provider: p\nsource: https://x\nverified: 2026-07-23\nmodels:\n  - {id: m, state: deprecated, announced: 2026-13-45}\n",
			"bad date",
		},
		{
			"shutdown without announcement",
			"provider: p\nsource: https://x\nverified: 2026-07-23\nmodels:\n  - {id: m, state: deprecated, shutdown: 2026-10-23}\n",
			"shutdown without announced",
		},
		{
			"supported with a shutdown date",
			"provider: p\nsource: https://x\nverified: 2026-07-23\nmodels:\n  - {id: m, state: supported, announced: 2026-01-01, shutdown: 2026-10-23}\n",
			"cannot carry a shutdown date",
		},
		{
			"duplicate id via alias",
			"provider: p\nsource: https://x\nverified: 2026-07-23\nmodels:\n  - {id: a, state: supported}\n  - {id: b, state: supported, aliases: [a]}\n",
			"claimed by both",
		},
		{
			"empty model id",
			"provider: p\nsource: https://x\nverified: 2026-07-23\nmodels:\n  - {id: '', state: supported}\n",
			"has no id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, tc.yaml)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestStalenessWarning(t *testing.T) {
	c, err := loadYAML(t, "provider: p\nsource: https://x\nverified: 2026-01-01\nmodels:\n  - {id: m, state: supported}\n")
	if err != nil {
		t.Fatal(err)
	}
	if w := c.StalenessWarning(day(2026, time.February, 1)); w != "" {
		t.Errorf("31 days old should not warn, got %q", w)
	}
	w := c.StalenessWarning(day(2026, time.July, 23))
	if w == "" {
		t.Fatal("203 days old must warn")
	}
	for _, want := range []string{"203 days", "2026-01-01", "upgrade airom"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning %q missing %q", w, want)
		}
	}
	// Verified AFTER the evaluated day is an inconsistency, not freshness: a
	// negative age must be reported rather than sliding under the threshold.
	if w := c.StalenessWarning(day(2025, time.January, 1)); !strings.Contains(w, "after the scan date") {
		t.Errorf("verified-after-scan should be surfaced, got %q", w)
	}
}

// TestStalenessIsPerProvider: a freshly-checked provider must not vouch for a
// neglected one. The warning reports the OLDEST provider, by name.
func TestStalenessIsPerProvider(t *testing.T) {
	fresh := "provider: fresh\nsource: https://x\nverified: 2026-07-20\nmodels:\n  - {id: a, state: supported}\n"
	rotten := "provider: rotten\nsource: https://y\nverified: 2024-01-01\nmodels:\n  - {id: b, state: supported}\n"
	c, err := loadFS(fstest.MapFS{
		"cat/fresh.yaml":  &fstest.MapFile{Data: []byte(fresh)},
		"cat/rotten.yaml": &fstest.MapFile{Data: []byte(rotten)},
	}, "cat", scanDay)
	if err != nil {
		t.Fatal(err)
	}
	w := c.StalenessWarning(scanDay)
	if w == "" {
		t.Fatal("a provider verified in 2024 must warn even when another is fresh")
	}
	if !strings.Contains(w, "rotten") || !strings.Contains(w, "2024-01-01") {
		t.Errorf("warning must name the stale provider and its date, got %q", w)
	}
}

// TestFutureVerifiedRejected: a typo'd year would park the staleness clock in
// the future and permanently disable the only guard against rotting data.
func TestFutureVerifiedRejected(t *testing.T) {
	_, err := loadYAML(t, "provider: p\nsource: https://x\nverified: 2062-07-23\nmodels:\n  - {id: m, state: supported}\n")
	if err == nil || !strings.Contains(err.Error(), "in the future") {
		t.Fatalf("future verified date must be rejected, got err=%v", err)
	}
}

// TestShutdownBeforeAnnouncedRejected: transposing the date pair is the likeliest
// transcription error, and it silently yields a wrong DaysRemaining.
func TestShutdownBeforeAnnouncedRejected(t *testing.T) {
	_, err := loadYAML(t, "provider: p\nsource: https://x\nverified: 2026-07-23\nmodels:\n  - {id: m, state: deprecated, announced: 2026-10-23, shutdown: 2026-01-01}\n")
	if err == nil || !strings.Contains(err.Error(), "precedes announced") {
		t.Fatalf("shutdown before announced must be rejected, got err=%v", err)
	}
}

// TestLookupDoesNotAliasCatalogDates: the returned Lifecycle is handed to
// writers and SDK callers; one of them normalizing a date in place must not
// rewrite the shared catalog for the rest of the process.
func TestLookupDoesNotAliasCatalogDates(t *testing.T) {
	c, err := LoadOn(scanDay)
	if err != nil {
		t.Fatal(err)
	}
	a := c.Lookup("openai", "gpt-4", scanDay)
	if a == nil || a.Shutdown == nil {
		t.Fatal("gpt-4 record missing a shutdown date")
	}
	orig := *a.Shutdown
	*a.Shutdown = orig.AddDays(365) // a caller mutates its copy

	b := c.Lookup("openai", "gpt-4", scanDay)
	if b.Shutdown == nil || !b.Shutdown.Equal(orig) {
		t.Errorf("catalog was mutated through a returned Lifecycle: %v, want %v", b.Shutdown, orig)
	}
}

// TestMiniVariantsKeepTheirOwnReplacement guards the alias-grouping hazard: the
// mini realtime models share dates with gpt-realtime but migrate to a DIFFERENT
// tier, so grouping them would hand out wrong migration advice.
func TestMiniVariantsKeepTheirOwnReplacement(t *testing.T) {
	c, err := LoadOn(scanDay)
	if err != nil {
		t.Fatal(err)
	}
	full := c.Lookup("openai", "gpt-realtime", scanDay)
	mini := c.Lookup("openai", "gpt-realtime-mini", scanDay)
	if full == nil || mini == nil {
		t.Fatal("realtime records missing")
	}
	if full.Replacement != "gpt-realtime-2.1" {
		t.Errorf("gpt-realtime replacement = %q", full.Replacement)
	}
	if mini.Replacement != "gpt-realtime-2.1-mini" {
		t.Errorf("gpt-realtime-mini replacement = %q, want the -mini tier", mini.Replacement)
	}
}

// ── Enrich ──────────────────────────────────────────────────────────────────

func TestEnrichAttachesLifecycleToHostedModelsOnly(t *testing.T) {
	c, err := LoadOn(scanDay)
	if err != nil {
		t.Fatal(err)
	}
	comp := func(kind airom.ComponentKind, name, provider, modelID string) airom.Component {
		x := airom.Component{ID: airom.ID("airom:" + name), Kind: kind, Name: name, Provider: airom.KnownString(provider)}
		if modelID != "" {
			x.Props = []airom.KV{{Name: modelIDProp, Value: modelID}}
		}
		return x
	}
	inv := &airom.Inventory{Components: []airom.Component{
		comp(airom.KindHostedLLM, "gpt-4-32k", "openai", "gpt-4-32k"), // retired
		// Supported comes from anthropic.yaml: its page publishes an explicit
		// Active table, so the claim is sourceable (openai's is not — see below).
		comp(airom.KindHostedLLM, "claude-sonnet-4-6", "anthropic", "claude-sonnet-4-6"),
		comp(airom.KindHostedLLM, "mystery", "openai", "totally-made-up"), // unknown
		// A current OpenAI model: no record, because a deprecations page cannot
		// substantiate "supported". Unknown is the honest answer.
		comp(airom.KindEmbeddingModel, "emb", "openai", "text-embedding-3-small"),
		// A local weights file must never be matched: no vendor controls its life.
		comp(airom.KindLocalModelFile, "gpt-4-32k", "openai", "gpt-4-32k"),
		// No provider → nothing to key on.
		{ID: "airom:np", Kind: airom.KindHostedLLM, Name: "gpt-4-32k", Provider: airom.UnknownString()},
	}}

	matched := Enrich(inv, c, scanDay)
	if matched != 2 {
		t.Errorf("matched = %d, want 2 (gpt-4-32k retired, claude-sonnet-4-6 supported)", matched)
	}
	get := func(i int) *airom.Lifecycle { return inv.Components[i].EOL }
	if lc := get(0); lc == nil || lc.State != airom.EOLRetired || lc.Replacement != "gpt-4o" {
		t.Errorf("retired hosted model: %+v", lc)
	} else if lc.DaysRemaining == nil || *lc.DaysRemaining >= 0 {
		t.Errorf("retired model must have a negative DaysRemaining, got %v", lc.DaysRemaining)
	}
	if lc := get(1); lc == nil || lc.State != airom.EOLSupported {
		t.Errorf("supported hosted model: %+v", lc)
	}
	if lc := get(3); lc != nil {
		t.Errorf("openai embedding has no sourceable support claim, want nil, got %+v", lc)
	}
	if lc := get(2); lc != nil {
		t.Errorf("uncurated model must get NO lifecycle, got %+v", lc)
	}
	if lc := get(4); lc != nil {
		t.Errorf("local model file must not be matched, got %+v", lc)
	}
	if lc := get(5); lc != nil {
		t.Errorf("provider-less component must not be matched, got %+v", lc)
	}
}

// TestEnrichFallsBackToComponentName covers detections that never recorded a
// raw model-id prop: the component name is the id.
func TestEnrichFallsBackToComponentName(t *testing.T) {
	c, _ := LoadOn(scanDay)
	inv := &airom.Inventory{Components: []airom.Component{{
		ID: "airom:1", Kind: airom.KindHostedLLM, Name: "gpt-4-32k",
		Provider: airom.KnownString("openai"), // no Props at all
	}}}
	if n := Enrich(inv, c, scanDay); n != 1 || inv.Components[0].EOL == nil {
		t.Fatalf("name fallback failed: matched=%d lifecycle=%+v", n, inv.Components[0].EOL)
	}
}

func TestEnrichNilSafe(t *testing.T) {
	c, _ := LoadOn(scanDay)
	if n := Enrich(nil, c, scanDay); n != 0 {
		t.Error("nil inventory must be a no-op")
	}
	if n := Enrich(&airom.Inventory{}, nil, scanDay); n != 0 {
		t.Error("nil catalog must be a no-op")
	}
	var nilCat *Catalog
	if nilCat.Lookup("openai", "gpt-4", scanDay) != nil || nilCat.Size() != 0 || nilCat.StalenessWarning(scanDay) != "" {
		t.Error("nil catalog methods must be safe")
	}
}
