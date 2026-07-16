package app

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Roro1727/airom/internal/ruleengine"
	"github.com/Roro1727/airom/internal/ruleengine/ruletest"
)

// EmbeddedRules is the built-in rule-pack filesystem (rules/**). It is set
// once, from the rules embed package, by the composition root — kept as a
// var so the SDK stays free of a go:embed dependency and tests can inject an
// empty set. nil means "no embedded packs".
var EmbeddedRules fs.FS

// loadRuleset assembles the effective ruleset: embedded defaults plus the
// configured --rules overlays.
func loadRuleset(cfg *Config) (*ruleengine.Ruleset, error) {
	rs, err := ruleengine.Load(EmbeddedRules, cfg.RulePaths, os.ReadFile)
	if err != nil {
		return nil, &UsageError{Err: err}
	}
	return rs, nil
}

// RulesList returns the effective compiled ruleset (each rule with its
// originating layer) for `airom rules list`.
func RulesList(cfg *Config) ([]ruleengine.EffectiveRule, error) {
	rs, err := loadRuleset(cfg)
	if err != nil {
		return nil, err
	}
	return rs.Rules, nil
}

// RulesLint validates a single user rule-pack file against the full lint
// contract and reports its fixture coverage (docs/rule-schema.md). fixtures
// are expected under <pack-dir>/testdata/<pack>/ when present.
func RulesLint(path string) (*ruletest.Report, error) {
	rs, err := ruleengine.Load(nil, []string{path}, os.ReadFile)
	if err != nil {
		return nil, &UsageError{Err: err}
	}
	m, err := ruleengine.Compile(rs)
	if err != nil {
		return nil, err
	}
	dir := fixturesDirFor(path)
	if _, statErr := os.Stat(dir); statErr != nil {
		// Compilation already validated the lint contract items 1-9; only
		// fixture coverage (item 10) needs a testdata dir.
		return &ruletest.Report{}, fmt.Errorf("no fixtures at %s: every rule needs ≥1 positive and ≥1 negative fixture (rule-schema.md item 10)", dir)
	}
	return ruletest.Run(m, dir)
}

// RulesTest runs a user rule pack against its fixtures for `airom rules test`.
func RulesTest(path string) (*ruletest.Report, error) {
	return ruletest.RunPackFile(path, fixturesDirFor(path))
}

// fixturesDirFor maps a pack file to its fixture directory:
// rules/models/openai.yaml -> rules/models/testdata/openai.
func fixturesDirFor(packPath string) string {
	dir := filepath.Dir(packPath)
	stem := stemOf(filepath.Base(packPath))
	return filepath.Join(dir, "testdata", stem)
}

func stemOf(name string) string {
	if ext := filepath.Ext(name); ext != "" {
		return name[:len(name)-len(ext)]
	}
	return name
}
