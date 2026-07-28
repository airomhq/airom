package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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
