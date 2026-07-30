// Package osv is the opt-in CVE overlay: it matches the AI packages AIROM
// inventoried (by their purl) against the OSV.dev advisory database and attaches
// the resulting CVEs to those components. It is scoped to AI dependencies, not a
// general-purpose SCA scanner, and it is off by default — querying a live
// database means the result is neither offline nor deterministic over time.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// DefaultEndpoint is the OSV.dev single-package query API.
const DefaultEndpoint = "https://api.osv.dev/v1/query"

// Doer is the subset of *http.Client the client needs — an interface so tests
// inject an httptest server instead of hitting the live API.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Options parameterize enrichment.
type Options struct {
	Endpoint    string // default DefaultEndpoint
	HTTP        Doer   // default http.DefaultClient
	Concurrency int    // default 8
	// SkipTestOnly omits components whose evidence is entirely test
	// scaffolding. Their advisories are hidden from the table, SARIF, and the
	// gate anyway, so querying them spends real network round-trips (and
	// somebody's rate limit) on answers nobody will be shown. A repository of
	// fixtures is the common case, not the rare one: AIROM's own tree is 180
	// test-only components out of 185.
	SkipTestOnly bool
}

// pkgEcosystems are the purl types OSV matches on — the package ecosystems
// AIROM emits. pkg:generic (weights), pkg:huggingface, and pkg:oci are skipped:
// OSV has no package-vuln data for them.
var pkgEcosystems = map[string]bool{
	"pypi": true, "npm": true, "golang": true, "cargo": true, "maven": true, "nuget": true,
}

// Enrich queries OSV for every component with a versioned package purl and
// attaches the matching CVEs. It mutates inv in place and returns the number of
// components that could not be checked. A query failure degrades honestly: the
// affected component simply carries no CVEs and a warning is recorded in
// inv.Stats.Warnings — the scan still succeeds. The returned count lets a caller
// with an active CVE gate fail closed rather than silently pass on an outage.
func Enrich(ctx context.Context, inv *airom.Inventory, opts Options) int {
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	client := opts.HTTP
	if client == nil {
		// A per-request deadline: without one, an endpoint that accepts the
		// connection but never responds would hang a worker (and eventually the
		// whole scan) until the run is interrupted.
		client = &http.Client{Timeout: 20 * time.Second}
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 8
	}

	// Collect the queryable components (versioned package purls).
	type job struct{ idx int }
	var jobs []job
	skipped, unresolved := 0, 0
	for i := range inv.Components {
		c := &inv.Components[i]
		if queryablePurl(c.PURL) {
			if opts.SkipTestOnly && c.TestOnly {
				skipped++
				continue
			}
			jobs = append(jobs, job{i})
			continue
		}
		// Declared as a range and never resolved: there is no version to ask
		// OSV about. Counted so the absence of findings can be explained
		// rather than read as an all-clear.
		if c.VersionConstraint != "" && c.Package != nil && pkgEcosystems[c.Package.Ecosystem] {
			if opts.SkipTestOnly && c.TestOnly {
				continue // already accounted for by the test-scope warning
			}
			unresolved++
		}
	}
	// The native and CycloneDX documents still CARRY these components, so an
	// absent `vulnerabilities` list on them would be indistinguishable from
	// "queried, nothing found". Say which it is: a consumer filtering CDX for
	// `scope: excluded` — a legitimate "what does this tree touch anywhere?"
	// read — must not take silence for an all-clear.
	if skipped > 0 {
		inv.Stats.Warnings = append(inv.Stats.Warnings, fmt.Sprintf(
			"cve: %d test-scoped component(s) were not checked against OSV.dev; re-run with --include-tests to check them",
			skipped,
		))
	}
	// The same reasoning, for the other reason a component goes unchecked. An
	// advisory range cannot be evaluated against "^4.20.0" — every answer OSV
	// could give would be about a release nobody has confirmed is installed.
	// Saying so beats reporting zero vulnerabilities and letting that read as
	// a clean bill of health.
	if unresolved > 0 {
		inv.Stats.Warnings = append(inv.Stats.Warnings, fmt.Sprintf(
			"cve: %d component(s) declare a version range and were not checked against OSV.dev; commit a lockfile or scan a deployed environment to resolve them",
			unresolved,
		))
	}
	if skipped > 0 || unresolved > 0 {
		sort.Strings(inv.Stats.Warnings)
	}
	if len(jobs) == 0 {
		return 0
	}

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	errSet := map[string]bool{} // distinct error strings, for a deterministic warning

	for _, jb := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			version, _ := inv.Components[idx].Version.Value()
			vulns, err := query(ctx, client, endpoint, inv.Components[idx].PURL, version)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				errSet[err.Error()] = true
				return
			}
			if len(vulns) > 0 {
				sort.Slice(vulns, func(a, b int) bool { return vulns[a].ID < vulns[b].ID })
				inv.Components[idx].Vulnerabilities = vulns
			}
		}(jb.idx)
	}
	wg.Wait()

	if failed > 0 {
		// A sorted, deduped set of the distinct errors keeps the warning
		// byte-stable for a fixed set of responses (P7), unlike naming whichever
		// goroutine happened to fail first.
		reasons := make([]string, 0, len(errSet))
		for e := range errSet {
			reasons = append(reasons, e)
		}
		sort.Strings(reasons)
		inv.Stats.Warnings = append(inv.Stats.Warnings, fmt.Sprintf(
			"cve: %d of %d component(s) could not be checked against OSV.dev (%s)",
			failed, len(jobs), strings.Join(reasons, "; "),
		))
		sort.Strings(inv.Stats.Warnings)
	}
	return failed
}

// queryablePurl reports whether p is a versioned package purl OSV can match.
func queryablePurl(p string) bool {
	if !strings.HasPrefix(p, "pkg:") || !strings.Contains(p, "@") {
		return false // no ecosystem, or no version to pin the advisory range
	}
	typ, _, _ := strings.Cut(strings.TrimPrefix(p, "pkg:"), "/")
	return pkgEcosystems[typ]
}

// ── OSV wire types ──────────────────────────────────────────────────────────

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}
type osvVuln struct {
	ID               string          `json:"id"`
	Summary          string          `json:"summary"`
	Aliases          []string        `json:"aliases"`
	Severity         []osvSeverity   `json:"severity"`
	Affected         []osvAffected   `json:"affected"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}
type osvSeverity struct {
	Type  string `json:"type"`  // CVSS_V2 | CVSS_V3 | CVSS_V4
	Score string `json:"score"` // a vector string
}
type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}
type osvRange struct {
	Type   string              `json:"type"`   // ECOSYSTEM | SEMVER | GIT
	Events []map[string]string `json:"events"` // {"introduced":"0"} / {"fixed":"1.2.3"}
}

// query posts one purl to OSV and converts the response to airom.Vulnerability.
// version is the component's installed version (may be ""), used to select the
// fix that actually applies to it.
func query(ctx context.Context, client Doer, endpoint, purl, version string) ([]airom.Vulnerability, error) {
	body, _ := json.Marshal(map[string]any{"package": map[string]string{"purl": purl}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var r osvResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}
	out := make([]airom.Vulnerability, 0, len(r.Vulns))
	for _, v := range r.Vulns {
		out = append(out, toVuln(v, version))
	}
	return dedupeByID(out), nil
}

// dedupeByID collapses advisories that resolve to the same id (e.g. a GHSA and
// a PYSEC record both aliasing one CVE): keep the most severe, prefer a real
// version for the fix, and union the aliases.
func dedupeByID(vulns []airom.Vulnerability) []airom.Vulnerability {
	idx := map[string]int{}
	var out []airom.Vulnerability
	for _, v := range vulns {
		i, ok := idx[v.ID]
		if !ok {
			idx[v.ID] = len(out)
			out = append(out, v)
			continue
		}
		m := &out[i]
		if moreSevere(v, *m) {
			m.Severity, m.Score, m.Vector = v.Severity, v.Score, v.Vector
		}
		if versionShaped(v.Fixed) && !versionShaped(m.Fixed) {
			m.Fixed = v.Fixed
		} else if m.Fixed == "" {
			m.Fixed = v.Fixed
		}
		if m.Summary == "" {
			m.Summary = v.Summary
		}
		m.Aliases = unionAliases(m.ID, m.Aliases, v.Aliases)
	}
	return out
}

// moreSevere ranks a above b by CVSS score, then severity bucket.
func moreSevere(a, b airom.Vulnerability) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return sevRank(a.Severity) > sevRank(b.Severity)
}

func sevRank(s airom.VulnSeverity) int {
	switch s {
	case airom.VulnCritical:
		return 4
	case airom.VulnHigh:
		return 3
	case airom.VulnMedium:
		return 2
	case airom.VulnLow:
		return 1
	default:
		return 0
	}
}

// unionAliases merges alias lists, dropping the display id, deduped and sorted.
func unionAliases(id string, a, b []string) []string {
	seen := map[string]bool{id: true}
	var out []string
	for _, x := range append(append([]string{}, a...), b...) {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// toVuln maps one OSV advisory to an airom.Vulnerability: prefer a CVE id,
// derive severity from the CVSS v3 vector (else the advisory's text severity),
// and name the fixed version that applies to the installed version.
func toVuln(v osvVuln, version string) airom.Vulnerability {
	id, aliases := preferCVE(v.ID, v.Aliases)
	score, vector, sev := severityOf(v)
	return airom.Vulnerability{
		ID:       id,
		Aliases:  aliases,
		Severity: sev,
		Score:    score,
		Vector:   vector,
		Summary:  v.Summary,
		Fixed:    firstFixed(v.Affected, version),
		Source:   "osv.dev",
		URL:      "https://osv.dev/vulnerability/" + v.ID,
	}
}

// preferCVE returns a CVE id (from the id or aliases) when one exists, with the
// remaining ids as aliases; otherwise it keeps the original id.
func preferCVE(id string, aliases []string) (string, []string) {
	all := append([]string{id}, aliases...)
	chosen := id
	for _, a := range all {
		if strings.HasPrefix(a, "CVE-") {
			chosen = a
			break
		}
	}
	rest := make([]string, 0, len(all))
	for _, a := range all {
		if a != chosen {
			rest = append(rest, a)
		}
	}
	sort.Strings(rest)
	return chosen, rest
}

// severityOf derives (score, vector, severity): a CVSS v3 vector is computed;
// otherwise the vector (v2/v4) is kept for display and severity falls back to
// the advisory's database_specific.severity text, then "unknown".
func severityOf(v osvVuln) (float64, string, airom.VulnSeverity) {
	vector := ""
	for _, s := range v.Severity {
		if vector == "" {
			vector = s.Score
		}
		if strings.HasPrefix(s.Score, "CVSS:3") {
			if sc, ok := cvssV3Score(s.Score); ok {
				return sc, s.Score, airom.SeverityFromScore(sc)
			}
		}
	}
	return 0, vector, textSeverity(v.DatabaseSpecific)
}

// textSeverity maps a GHSA-style database_specific.severity string.
func textSeverity(raw json.RawMessage) airom.VulnSeverity {
	var ds struct {
		Severity string `json:"severity"`
	}
	_ = json.Unmarshal(raw, &ds)
	switch strings.ToUpper(ds.Severity) {
	case "CRITICAL":
		return airom.VulnCritical
	case "HIGH":
		return airom.VulnHigh
	case "MODERATE", "MEDIUM":
		return airom.VulnMedium
	case "LOW":
		return airom.VulnLow
	default:
		return airom.VulnUnknown
	}
}

// firstFixed returns the "fixed" version that applies to the installed version.
// An advisory for a long-lived package carries several ranges — a backport line
// (`< 1.5.0`) and the current line (`>= 2.0.0, < 2.3.0`) — each with its own
// fixed endpoint. Reporting the *first* one tells a user on 2.1.0 to "fix" by
// going to 1.5.0, which is wrong: the actionable fix is the smallest fixed
// version strictly greater than what they run. When the installed version is
// unknown or unparseable, fall back to the first real (non-GIT) fixed version;
// a GIT commit hash is used only if no real version exists.
func firstFixed(affected []osvAffected, version string) string {
	var realFixed []string // non-GIT fixed versions, in encounter order
	gitFallback := ""
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				f := e["fixed"]
				if f == "" {
					continue
				}
				if r.Type == "GIT" {
					if gitFallback == "" {
						gitFallback = f
					}
					continue
				}
				realFixed = append(realFixed, f)
			}
		}
	}
	if len(realFixed) == 0 {
		return gitFallback
	}
	// Version-aware pick: the next release on the installed line.
	if v, ok := parseVersion(version); ok {
		best, haveBest := "", false
		var bestV []int
		for _, f := range realFixed {
			fv, ok := parseVersion(f)
			if !ok || compareVersions(fv, v) <= 0 {
				continue
			}
			if !haveBest || compareVersions(fv, bestV) < 0 {
				best, bestV, haveBest = f, fv, true
			}
		}
		if haveBest {
			return best
		}
	}
	return realFixed[0]
}

// parseVersion extracts the leading dotted-numeric release components of a
// version string (dropping a "v" prefix and stopping at the first pre-release or
// build separator) for a best-effort, ecosystem-agnostic ordering. So
// "1.0.0-rc1" → [1 0 0], not [1 0 0 1]. Returns false when no numeric component
// leads the string (a commit hash, a date tag we can't order).
func parseVersion(s string) ([]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	var out []int
	cur := ""
	flush := func() {
		if cur != "" {
			n, _ := strconv.Atoi(cur)
			out = append(out, n)
			cur = ""
		}
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			cur += string(r)
		case r == '.' && cur != "":
			flush()
		default:
			// A pre-release/build separator (or a leading dot): the numeric
			// release portion ends here.
			flush()
			if len(out) == 0 {
				return nil, false
			}
			return out, true
		}
	}
	flush()
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// compareVersions orders two parsed version component slices, treating a missing
// trailing component as 0 (so 1.5 == 1.5.0). Returns -1, 0, or 1.
func compareVersions(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(a) {
			ai = a[i]
		}
		if i < len(b) {
			bi = b[i]
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	return 0
}

// versionShaped reports whether s looks like a package version (has a digit and
// isn't a 40-char git SHA), so a real version is preferred over a commit hash.
func versionShaped(s string) bool {
	if s == "" {
		return false
	}
	if len(s) == 40 && isHex(s) {
		return false
	}
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
