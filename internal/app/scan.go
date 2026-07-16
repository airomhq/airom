package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/Roro1727/airom/internal/assemble"
	"github.com/Roro1727/airom/internal/detectors/all"
	"github.com/Roro1727/airom/internal/dispatch"
	"github.com/Roro1727/airom/internal/engine"
	"github.com/Roro1727/airom/internal/ruleengine"
	"github.com/Roro1727/airom/internal/source"
	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Tool identifies this build in every produced AIBOM; the CLI stamps it
// from the ldflags build metadata before running any command.
var Tool = airom.ToolInfo{Name: "airom", Version: "dev"}

// buildCatalog composes the detector catalog: generated built-ins plus the
// rule-engine detector when the effective ruleset is non-empty (§6.2 —
// explicit construction, compiled matcher via constructor, no globals).
func buildCatalog(cfg *Config) (*engine.Catalog, *ruleengine.Matcher, error) {
	ruleset, err := ruleengine.Load(EmbeddedRules, cfg.RulePaths, os.ReadFile)
	if err != nil {
		return nil, nil, &UsageError{Err: err}
	}
	matcher, err := ruleengine.Compile(ruleset)
	if err != nil {
		return nil, nil, err
	}

	catalog := engine.NewCatalog()
	for _, d := range all.Builtin() {
		catalog.Add(d)
	}
	if !matcher.Empty() {
		catalog.Add(ruleengine.NewDetector(matcher))
	}
	return catalog, matcher, nil
}

// runScanPipeline executes the full pipeline over an acquired source:
// phase 1 (engine + dispatcher) → phase 2 (project detectors) → assembly.
func runScanPipeline(ctx context.Context, cfg *Config, src source.Source) (*airom.Inventory, error) {
	catalog, _, err := buildCatalog(cfg)
	if err != nil {
		return nil, err
	}
	sel, err := catalog.Select(cfg.Select)
	if err != nil {
		return nil, &UsageError{Err: err}
	}

	disp, err := dispatch.New(sel.File)
	if err != nil {
		return nil, err
	}

	eng := engine.New(engine.Options{
		Parallel:    cfg.Parallel,
		IOBudget:    cfg.IOBudget,
		MaxFileSize: cfg.MaxFileSize,
	})
	out, err := eng.Scan(ctx, src, disp)
	if err != nil {
		return nil, fmt.Errorf("scan %q: %w", cfg.Target, err)
	}

	var findings []detect.Finding
	var unknowns []airom.Unknown
	for _, p := range out.Payloads {
		res, ok := p.Value.(*dispatch.Result)
		if !ok {
			continue
		}
		findings = append(findings, res.Findings...)
		unknowns = append(unknowns, res.Unknowns...)
	}
	for _, u := range out.Unknowns {
		unknowns = append(unknowns, airom.Unknown{Path: u.Path, DetectorID: u.Stage, Reason: u.Reason})
	}

	// FilesFailed = distinct files with ANY unknown, including per-detector
	// failures the dispatcher attributed inside payloads — the engine alone
	// undercounts them (§14 honesty block).
	failedPaths := map[string]bool{}
	for _, u := range unknowns {
		failedPaths[u.Path] = true
	}

	// Phase 2: flat project-detector set over the pull resolver (§8).
	// Cancellation aborts the scan — it must never truncate silently.
	view := detect.NewFindingsView(findings)
	p2, err := dispatch.RunProject(ctx, sel.Project, dispatch.ResolverAdapter{R: src.Resolver()}, view, cfg.Parallel)
	if err != nil {
		return nil, fmt.Errorf("scan %q (phase 2): %w", cfg.Target, err)
	}
	findings = append(findings, p2.Findings...)
	unknowns = append(unknowns, p2.Unknowns...)

	// Per-detector accounting covers both phases (file and project
	// detector IDs are disjoint by catalog construction).
	detStats := append(disp.Stats(), p2.Stats...)
	sort.Slice(detStats, func(i, j int) bool { return detStats[i].ID < detStats[j].ID })

	stats := airom.ScanStats{
		FilesWalked:    out.Stats.FilesWalked,
		FilesProcessed: out.Stats.FilesProcessed,
		FilesFailed:    int64(len(failedPaths)),
		HeaderBytes:    out.Stats.HeaderBytes,
		ContentBytes:   out.Stats.ContentBytes,
		Duration:       out.Stats.Duration,
		Selection:      sel.Explanation,
		Detectors:      detStats,
	}

	info := src.Info()
	return assemble.Build(findings, unknowns, stats, assemble.Options{
		Tool:      Tool,
		Source:    airom.SourceInfo{Kind: string(info.Kind), Target: info.Target},
		Lifecycle: "pre-build",
		Serial:    newSerial(),
		Timestamp: time.Now().UTC(),
	}), nil
}

// newSerial produces a RFC 4122 v4 UUID URN without a dependency.
func newSerial() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "urn:uuid:00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// DetectorInfo is one catalog entry for `airom detectors list/explain`.
type DetectorInfo struct {
	ID         string
	Version    int
	Phase      string // "file" | "project"
	Selector   detect.Selector
	SelectedBy string // explanation token, "" when excluded by --select
	RuleCount  int    // >0 for the rule-engine detector
}

// Detectors resolves the catalog (honoring --rules and --select) into the
// self-documenting capability view (§6.2).
func Detectors(cfg *Config) ([]DetectorInfo, error) {
	catalog, matcher, err := buildCatalog(cfg)
	if err != nil {
		return nil, err
	}
	sel, err := catalog.Select(cfg.Select)
	if err != nil {
		return nil, &UsageError{Err: err}
	}

	selectedBy := map[string]string{}
	for _, line := range sel.Explanation {
		id, why, ok := cutExplanation(line)
		if ok {
			selectedBy[id] = why
		}
	}

	var out []DetectorInfo
	for _, d := range catalog.All() {
		info := DetectorInfo{
			ID:         d.ID(),
			Version:    d.Version(),
			Selector:   d.Selector(),
			SelectedBy: selectedBy[d.ID()],
			Phase:      "file",
		}
		if _, ok := d.(detect.ProjectDetector); ok {
			info.Phase = "project"
		}
		if d.ID() == "ruleengine" && matcher != nil {
			info.RuleCount = len(matcher.Rules())
		}
		out = append(out, info)
	}
	return out, nil
}

func cutExplanation(line string) (id, why string, ok bool) {
	for i := 0; i < len(line)-1; i++ {
		if line[i] == ':' && line[i+1] == ' ' {
			return line[:i], line[i+2:], true
		}
	}
	return "", "", false
}
