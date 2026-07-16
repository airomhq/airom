package rules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Roro1727/airom/internal/ruleengine"
	"github.com/Roro1727/airom/internal/ruleengine/ruletest"
)

// categories are the embedded rule-pack directories.
var categories = []string{
	"models", "embeddings", "frameworks", "vectordb",
	"infra", "params", "prompts", "datasets",
}

// TestEmbeddedRulesetLoads compiles the ENTIRE embedded set exactly as the
// binary does at startup: global ID uniqueness, the full lint contract, and
// the Aho-Corasick build. A single invalid rule fails here (and would abort
// the real binary).
func TestEmbeddedRulesetLoads(t *testing.T) {
	rs, err := ruleengine.Load(FS(), nil, os.ReadFile)
	if err != nil {
		t.Fatalf("embedded ruleset does not load: %v", err)
	}
	if _, err := ruleengine.Compile(rs); err != nil {
		t.Fatalf("embedded ruleset does not compile: %v", err)
	}
	if len(rs.Rules) == 0 {
		t.Fatal("embedded ruleset is empty")
	}
	t.Logf("embedded ruleset: %d rules across %d categories", len(rs.Rules), len(categories))
}

// TestEmbeddedPackFixtures runs every pack against its annotated fixtures
// and enforces the ≥1-positive-and-≥1-negative-per-rule contract
// (docs/rule-schema.md item 10).
func TestEmbeddedPackFixtures(t *testing.T) {
	packs := discoverPacks(t)
	if len(packs) == 0 {
		t.Fatal("no rule packs found")
	}
	for _, pack := range packs {
		t.Run(pack.rel, func(t *testing.T) {
			fixturesDir := filepath.Join(pack.dir, "testdata", pack.stem)
			if _, err := os.Stat(fixturesDir); err != nil {
				t.Fatalf("pack %s has no fixtures at %s (every rule needs positive+negative fixtures)", pack.rel, fixturesDir)
			}
			report, err := ruletest.RunPackFile(pack.path, fixturesDir)
			if err != nil {
				t.Fatalf("run pack: %v", err)
			}
			for _, f := range report.Failures {
				t.Errorf("%s:%d %s: %s", f.File, f.Line, f.RuleID, f.Reason)
			}
			for _, id := range report.RulesMissingPositive {
				t.Errorf("rule %s: no positive fixture (# airom: %s)", id, id)
			}
			for _, id := range report.RulesMissingNegative {
				t.Errorf("rule %s: no negative fixture (# airom-ok: %s)", id, id)
			}
		})
	}
}

type packInfo struct {
	path, dir, rel, stem string
}

func discoverPacks(t *testing.T) []packInfo {
	t.Helper()
	var out []packInfo
	for _, cat := range categories {
		entries, err := os.ReadDir(cat)
		if err != nil {
			continue // a category with no packs is allowed
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			path := filepath.Join(cat, e.Name())
			out = append(out, packInfo{
				path: path,
				dir:  cat,
				rel:  path,
				stem: strings.TrimSuffix(e.Name(), ".yaml"),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out
}
