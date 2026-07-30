package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/airomhq/airom/internal/assemble"
	"github.com/airomhq/airom/internal/compliance"
	"github.com/airomhq/airom/internal/detectors/all"
	"github.com/airomhq/airom/internal/dispatch"
	"github.com/airomhq/airom/internal/engine"
	"github.com/airomhq/airom/internal/eol"
	"github.com/airomhq/airom/internal/osv"
	"github.com/airomhq/airom/internal/ruleengine"
	"github.com/airomhq/airom/internal/source"
	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

// Tool identifies this build in every produced AIBOM; the CLI stamps it
// from the ldflags build metadata before running any command.
var Tool = airom.ToolInfo{Name: "airom", Version: "dev"}

// loadEmbeddedEOLCatalog is a seam. The embedded catalog cannot fail in
// practice (CI validates it), so the failure path — the one that decides
// whether an unevaluated gate fails closed — is otherwise unreachable from a
// test, which is exactly the kind of code that rots.
var loadEmbeddedEOLCatalog = eol.Load

// buildCatalog composes the detector catalog: generated built-ins plus the
// rule-engine detector when the effective ruleset is non-empty (§6.2 —
// explicit construction, compiled matcher via constructor, no globals).
func buildCatalog(cfg *Config) (*engine.Catalog, *ruleengine.Matcher, string, error) {
	ruleset, rulesVersion, err := loadRuleset(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	matcher, err := ruleengine.Compile(ruleset)
	if err != nil {
		return nil, nil, "", err
	}

	catalog := engine.NewCatalog()
	for _, d := range all.Builtin() {
		catalog.Add(d)
	}
	if !matcher.Empty() {
		catalog.Add(ruleengine.NewDetector(matcher))
	}
	return catalog, matcher, rulesVersion, nil
}

// runScanPipeline executes the full pipeline over an acquired source:
// phase 1 (engine + dispatcher) → phase 2 (project detectors) → assembly.
func runScanPipeline(ctx context.Context, cfg *Config, src source.Source) (*airom.Inventory, error) {
	// Before the ruleset is resolved, so a bundle installed now is the one this
	// scan actually uses rather than the next one.
	autoUpdateNote := autoUpdateRules(ctx, cfg)

	catalog, matcher, rulesVersion, err := buildCatalog(cfg)
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

	// Progress is presentation-only and stderr-only: it never reaches stdout,
	// so the emitted AIBOM stays byte-identical (P7). Disabled off a terminal.
	live, stopProgress := startProgress(cfg, cfg.Target)
	// Deferred, not merely called after Scan: a panic between here and there
	// would otherwise leave the cursor hidden and slog permanently routed
	// through a dead spinner. Stop is idempotent, so the explicit call below —
	// which ends the animation before anything is printed — still stands.
	defer stopProgress()

	eng := engine.New(engine.Options{
		Parallel:    cfg.Parallel,
		IOBudget:    cfg.IOBudget,
		MaxFileSize: cfg.MaxFileSize,
		Live:        live,
	})
	out, err := eng.Scan(ctx, src, disp)
	stopProgress()
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
	if autoUpdateNote != "" {
		stats.Warnings = append(stats.Warnings, autoUpdateNote)
	}

	// Stamp rule-pack provenance onto a per-scan copy of the tool identity (never
	// the package global): the effective-ruleset hash, and the active source —
	// "builtin" until PR4 wires a fetched bundle version through here.
	tool := Tool
	tool.RulesHash = matcher.Hash()
	tool.RulesVersion = rulesVersion

	// One clock read for the whole scan: the same instant stamps the BOM and
	// decides the EOL overlay's "has this shutdown arrived yet?", so the two can
	// never disagree — a BOM dated July cannot carry a state evaluated in
	// October. cfg.Now lets a golden suite pin the day.
	now := cfg.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	info := src.Info()
	inv := assemble.Build(findings, unknowns, stats, assemble.Options{
		Tool:      tool,
		Source:    airom.SourceInfo{Kind: string(info.Kind), Target: info.Target},
		Lifecycle: "pre-build",
		Serial:    newSerial(),
		Timestamp: now,
	})

	// The CVE overlay (opt-in) matches package purls against OSV.dev before
	// compliance runs, so a compliance control that maps to CVEs sees them. It
	// degrades honestly on a network failure (warnings, no CVEs) — never fatal…
	// EXCEPT when a CVE gate is active: a gate that silently passes because the
	// fetch failed is CI theater, so there we fail closed with a clear error
	// rather than let the outage look like a clean build.
	if cfg.CVE {
		if failed := osv.Enrich(ctx, inv, osv.Options{SkipTestOnly: !cfg.IncludeTests}); failed > 0 && cfg.Policy.ReferencesCVE() {
			return nil, fmt.Errorf(
				"cve gate (--fail-on %s) cannot be evaluated: %d component(s) could not be checked against OSV.dev; re-run when it is reachable",
				cfg.Policy, failed,
			)
		}
	}

	// The EOL overlay attaches provider retirement facts to hosted models. It
	// runs before compliance so a control mapping to "third-party lifecycle"
	// can see them, and — unlike the CVE overlay — it needs no network, so it
	// stays on under --offline. A catalog that fails to load costs the overlay
	// but not the AIBOM: warn and carry on, since omitting a claim is honest.
	// The exception is an active gate, which fails closed below.
	if !cfg.NoEOL {
		// Load validates catalog INTEGRITY against real time; the pinned scan
		// day is passed to Enrich, which is what decides whether a shutdown has
		// arrived. Sharing one clock would let a pinned past date reject a
		// catalog verified after it.
		cat, catSource, catWarn, err := loadEOLCatalogFor(cfg)
		if catWarn != "" {
			inv.Stats.Warnings = append(inv.Stats.Warnings, catWarn)
			sort.Strings(inv.Stats.Warnings)
		}
		switch {
		case err != nil && cfg.Policy.ReferencesEOL():
			// Fail closed, exactly as the CVE gate does. A gate evaluated
			// against an overlay that produced nothing can only ever pass, and
			// a green build is the one outcome that must never be a lie.
			return nil, fmt.Errorf(
				"eol gate (--fail-on %s) cannot be evaluated: the model lifecycle catalog failed to load: %w",
				cfg.Policy, err,
			)
		case err != nil:
			inv.Stats.Warnings = append(inv.Stats.Warnings,
				fmt.Sprintf("eol: model lifecycle catalog unavailable, no EOL findings reported (%v)", err))
			sort.Strings(inv.Stats.Warnings)
		default:
			eol.Enrich(inv, cat, airom.DateOf(now))
			// Recorded even when nothing matched: "this catalog had nothing to
			// say about your models" and "no catalog ran" are different claims.
			inv.Tool.EOLCatalog = catSource
		}
	}

	// Compliance mapping is a post-assembly overlay: evaluate the requested
	// frameworks against the finished inventory (§ risks.md sibling). An
	// unknown framework id is a usage error, surfaced with the valid set.
	if len(cfg.Compliance) > 0 {
		results, err := compliance.Evaluate(inv, cfg.Compliance, cfg.IncludeTests)
		if err != nil {
			return nil, &UsageError{Err: err}
		}
		inv.Compliance = results
	}
	return inv, nil
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
	catalog, matcher, _, err := buildCatalog(cfg)
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
