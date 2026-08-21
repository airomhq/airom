package fix

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
)

// Target is one package the CVE overlay found vulnerable, resolved to a single
// remediation: bump the pin at File:Line from Current to Fixed.
//
// A Target is emitted even when it cannot be applied (Fixable=false, Reason
// filled). Hiding an unfixable finding would turn "AIROM has no safe edit for
// this" into "this is fine" — the same honesty rule the scan itself follows
// when it refuses to guess a version.
type Target struct {
	Package   string // component name as the manifest spells it
	Ecosystem string // purl type: pypi, npm, golang, cargo, maven, nuget
	Current   string // the version the scan resolved
	Fixed     string // highest fixed version across this package's advisories

	Vulns    []Vuln             // every advisory on this package, most severe first
	Severity airom.VulnSeverity // the most severe bucket present

	// Major reports that Fixed crosses a major version boundary from Current.
	//
	// It is surfaced, never acted on. When the only release that clears an
	// advisory is two majors away, that IS the remediation — but it is also an
	// API break, and a tool that bumps it without saying so has traded a
	// disclosed vulnerability for an undisclosed build failure.
	Major bool

	// Sites is EVERY declared manifest that pins this version — not just one.
	//
	// A package can be pinned in several places at once: an api/ and a worker/
	// requirements.txt in the same repo, a monorepo with a manifest per service,
	// a root manifest beside a per-package one. Assembly merges those sightings
	// into a single component, so a fix that rewrote only the best-scoring
	// occurrence left the others declaring the vulnerable version, reported
	// "updated 1 pin", and told the user to re-scan to confirm — whereupon the
	// advisory was still there, because it genuinely still was. Reporting a
	// package fixed while it is still pinned vulnerable elsewhere is the
	// over-claim this tool exists not to make.
	Sites []Site

	Fixable bool
	Reason  string // why not, when Fixable is false
}

// Site is one manifest line that pins the vulnerable version.
type Site struct {
	File    string // manifest path, relative to the scan root
	Line    int    // 1-based line carrying the pin
	Snippet string // the line as the detector saw it
}

// String renders a site as the file:line a report points at.
func (s Site) String() string { return fmt.Sprintf("%s:%d", s.File, s.Line) }

// Vuln is the display slice of an advisory: enough to explain a row without
// dragging the whole CycloneDX vulnerability along.
type Vuln struct {
	ID       string
	Severity airom.VulnSeverity
	Score    float64
	Summary  string
	URL      string
	Fixed    string // the fixed version THIS advisory names ("" when it names none)
}

// declaredManifests are the detector IDs whose findings come from a manifest a
// human wrote and may therefore be rewritten.
//
// An allowlist rather than a lockfile denylist: a detector added tomorrow reads
// something new, and the safe default for "AIROM does not know what this file
// is" has to be "do not edit it". Everything absent from this map is reported
// with a Reason instead.
var declaredManifests = map[string]string{
	"manifest/pypi-requirements": "requirements.txt",
	"manifest/pypi-pyproject":    "pyproject.toml",
	"manifest/npm":               "package.json",
	"manifest/gomod":             "go.mod",
	"manifest/cargo":             "Cargo.toml",
	"manifest/gradle":            "build.gradle",
	"manifest/nuget":             "*.csproj",
	// manifest/maven is deliberately absent: see derivedSources.
}

// derivedSources explains, per detector, why its finding is not a pin anyone
// should hand-edit. Used only for the message: the allowlist above is what
// actually decides.
var derivedSources = map[string]string{
	"manifest/pypi-lock":      "lockfile — regenerate it from the manifest instead",
	"manifest/pipfile-lock":   "lockfile — regenerate it from the manifest instead",
	"manifest/npm-lock":       "lockfile — regenerate it from the manifest instead",
	"manifest/yarn-lock":      "lockfile — regenerate it from the manifest instead",
	"manifest/pnpm-lock":      "lockfile — regenerate it from the manifest instead",
	"manifest/pypi-installed": "installed package metadata — reinstall instead of editing site-packages",
	// A frozen binary is a build output. There is no pin in it to rewrite, and
	// the manifest that produced it may not even be in this tree.
	"frozen/pyinstaller": "PyInstaller binary — fix the manifest it was built from and rebuild",
	// pom.xml IS hand-written, but the Maven detector records the line of the
	// <dependency> open tag, and the <version> lives on a later line. AIROM has
	// no line to rewrite, and pretending otherwise would fail every pom.xml fix
	// with a message claiming the user's file had changed when it had not.
	"manifest/maven": "pom.xml <dependency> block — the <version> is on another line, which AIROM does not track",
}

// Plan resolves every vulnerable component in inv into one Target, most severe
// first. Components with no advisories, or whose advisories name no fixed
// version, are left out entirely — there is nothing to offer.
//
// includeTests mirrors the table's own scoping: a component seen only in test
// scaffolding is hidden from the attention surfaces, and the fix table is one
// of them.
func Plan(inv *airom.Inventory, includeTests bool) []Target {
	if inv == nil {
		return nil
	}
	var out []Target
	for i := range inv.Components {
		c := &inv.Components[i]
		if len(c.Vulnerabilities) == 0 {
			continue
		}
		if c.TestOnly && !includeTests {
			continue
		}
		if t, ok := targetFor(c); ok {
			out = append(out, t)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := SeverityRank(out[i].Severity), SeverityRank(out[j].Severity); ri != rj {
			return ri > rj
		}
		return out[i].Package < out[j].Package
	})
	return out
}

// targetFor builds the Target for one vulnerable component, or reports that the
// component offers no remediation at all.
func targetFor(c *airom.Component) (Target, bool) {
	current, ok := c.Version.Value()
	if !ok || current == "" {
		return Target{}, false // no definite version means OSV never matched it
	}

	t := Target{
		Package:   c.Name,
		Ecosystem: ecosystemOf(c),
		Current:   current,
		Severity:  airom.VulnUnknown,
	}
	for _, v := range c.Vulnerabilities {
		t.Vulns = append(t.Vulns, Vuln{
			ID: v.ID, Severity: v.Severity, Score: v.Score,
			Summary: v.Summary, URL: v.URL, Fixed: v.Fixed,
		})
		if SeverityRank(v.Severity) > SeverityRank(t.Severity) {
			t.Severity = v.Severity
		}
	}
	sort.SliceStable(t.Vulns, func(i, j int) bool {
		if ri, rj := SeverityRank(t.Vulns[i].Severity), SeverityRank(t.Vulns[j].Severity); ri != rj {
			return ri > rj
		}
		return t.Vulns[i].ID < t.Vulns[j].ID
	})

	t.Fixed = highestFixed(t.Vulns, current)
	if t.Fixed == "" {
		return Target{}, false // no advisory names a version to move to
	}
	t.Major = crossesMajor(current, t.Fixed)

	sites, reason := pinSites(c, current)
	if len(sites) == 0 {
		t.Reason = reason
		return t, true
	}
	t.Sites = sites
	t.Fixable = true
	return t, true
}

// pinSites collects EVERY declared-manifest occurrence whose line spells out
// the version being replaced — because every one of them has to move for the
// package to stop being vulnerable. Returns a human reason when none qualify.
//
// Requiring the line to carry the version is what keeps the table honest about
// which rows are actionable. A component's Version is whatever the assembler
// resolved, which is routinely NOT what the manifest says: `"openai": "^4.0.0"`
// in package.json with a package-lock.json resolving 4.2.1 yields Version 4.2.1,
// and the same happens for `>=`/`~=` in requirements.txt beside a poetry or uv
// lock. Without this check such a component shows [ Fix ] and a target version,
// Apply then refuses with "no longer pins openai 4.2.1 — re-run the scan", and
// re-scanning reproduces it forever: a button that cannot work, and an error
// message that blames the user's file for something it never said.
//
// A range is a real answer, so it gets a real reason rather than a broken
// button. The check also catches, generically, any detector that points at a
// line the version does not live on.
func pinSites(c *airom.Component, current string) ([]Site, string) {
	var sites []Site
	var derived, unpinned string
	for i := range c.Evidence.Occurrences {
		o := &c.Evidence.Occurrences[i]
		if _, ok := declaredManifests[o.DetectorID]; !ok {
			if why, known := derivedSources[o.DetectorID]; known && derived == "" {
				derived = why
			}
			continue
		}
		if o.Location.Line <= 0 {
			continue
		}
		// The snippet is the line as the detector read it. When a detector
		// records none there is nothing to check here, and Apply's own re-read
		// remains the guard.
		if o.Snippet != "" && !declaresVersion(o.Snippet, current) {
			if unpinned == "" {
				unpinned = fmt.Sprintf("%s:%d declares a range, not %s — that version came from a lockfile or installed metadata",
					o.Location.Path, o.Location.Line, current)
			}
			continue
		}
		sites = append(sites, Site{File: o.Location.Path, Line: o.Location.Line, Snippet: o.Snippet})
	}

	// Deterministic order (P7): the report and the table list the same sites in
	// the same sequence on every run, whatever order detection happened to
	// produce.
	sort.SliceStable(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})

	switch {
	case len(sites) > 0:
		return sites, ""
	case unpinned != "":
		return nil, unpinned
	case derived != "":
		return nil, "only seen in a " + derived
	default:
		return nil, "no declared manifest pins this version"
	}
}

// declaresVersion reports whether snippet carries version as a whole token —
// the same test Apply will apply to the line itself, asked early so the table
// can mark the row instead of offering a button that is going to refuse.
func declaresVersion(snippet, version string) bool {
	_, ok := replaceVersion(snippet, version, version+"!")
	return ok
}

// ecosystemOf reads the purl type ("pkg:pypi/x@1" -> "pypi"), the one place a
// component states which packaging world it lives in.
func ecosystemOf(c *airom.Component) string {
	rest, ok := strings.CutPrefix(c.PURL, "pkg:")
	if !ok {
		return ""
	}
	typ, _, _ := strings.Cut(rest, "/")
	return typ
}

// highestFixed returns the largest fixed version named by any advisory, which
// is the single bump that clears all of them. Advisories whose "fixed" is a
// commit hash or an otherwise unorderable tag are skipped: a version we cannot
// order is a version we cannot prove is an upgrade.
//
// Returns "" when nothing orderable is above current — including the case where
// every named fix is already at or below the installed version, which means the
// advisory data disagrees with itself and AIROM has no honest bump to offer.
func highestFixed(vulns []Vuln, current string) string {
	cur, curOK := parseVersion(current)
	best, bestOK := "", false
	var bestV []int
	for _, v := range vulns {
		if v.Fixed == "" {
			continue
		}
		fv, ok := parseVersion(v.Fixed)
		if !ok {
			continue
		}
		if curOK && compareVersions(fv, cur) <= 0 {
			continue // already covered by what is installed
		}
		if !bestOK || compareVersions(fv, bestV) > 0 {
			best, bestV, bestOK = v.Fixed, fv, true
		}
	}
	return best
}

// crossesMajor reports whether moving from current to fixed leaves the
// compatibility line the ecosystem would have kept you on.
//
// The rule is npm's caret and Cargo's default in one sentence: while the major
// is 0 the MINOR carries compatibility (0.2.x to 0.3.x breaks, 0.0.310 to
// 0.0.339 does not), and from 1.0 onward the major does. Applied across
// ecosystems because it matches how their maintainers actually version, and
// because the alternative — warning on every bump — trains users to ignore the
// warning that matters.
func crossesMajor(current, fixed string) bool {
	a, aok := parseVersion(current)
	b, bok := parseVersion(fixed)
	if !aok || !bok {
		return false // unorderable: say nothing rather than guess
	}
	return compatLine(a) != compatLine(b)
}

// compatLine returns the [major, minor] pair that identifies a version's
// compatibility line, with the minor zeroed once the major is nonzero.
func compatLine(v []int) [2]int {
	var out [2]int
	if len(v) > 0 {
		out[0] = v[0]
	}
	if out[0] == 0 && len(v) > 1 {
		out[1] = v[1]
	}
	return out
}

// SeverityRank orders the CVSS buckets for sorting, highest first. Exported so
// every view of a plan — the table, the fallback report, the --fix-all summary
// — sorts by the one rule.
func SeverityRank(s airom.VulnSeverity) int {
	switch s {
	case airom.VulnCritical:
		return 5
	case airom.VulnHigh:
		return 4
	case airom.VulnMedium:
		return 3
	case airom.VulnLow:
		return 2
	default:
		return 1
	}
}

// parseVersion extracts the leading dotted-numeric release components of a
// version string (dropping a "v" prefix and stopping at the first pre-release or
// build separator), for a best-effort, ecosystem-agnostic ordering. So
// "1.0.0-rc1" -> [1 0 0]. Returns false when no numeric component leads the
// string — a commit hash or a date tag we cannot order.
//
// Deliberately the same rule internal/osv applies when it picks which fixed
// version an advisory is actually offering: the two must agree, or the table
// would name one version and the fix would write another.
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

// compareVersions orders two parsed version component slices, treating a
// missing trailing component as 0 (so 1.5 == 1.5.0). Returns -1, 0, or 1.
func compareVersions(a, b []int) int {
	n := max(len(a), len(b))
	for i := range n {
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

// Summary counts a plan for the one-line report after a non-interactive run.
type Summary struct {
	Fixable   int
	Unfixable int
	Vulns     int
}

// Summarize tallies a plan.
func Summarize(ts []Target) Summary {
	var s Summary
	for _, t := range ts {
		if t.Fixable {
			s.Fixable++
		} else {
			s.Unfixable++
		}
		s.Vulns += len(t.Vulns)
	}
	return s
}

// String renders a Target as the one line a log or a --fix-all report shows.
func (t Target) String() string {
	major := ""
	if t.Major {
		major = " [major bump]"
	}
	return fmt.Sprintf("%s %s -> %s%s (%d advisor%s, %s) at %s",
		t.Package, t.Current, t.Fixed, major, len(t.Vulns), plural(len(t.Vulns)),
		strings.ToUpper(string(t.Severity)), t.Where())
}

// Where names the sites a fix would touch: the first, plus a count when there
// are more. A package pinned in four manifests has to say so — "at
// api/requirements.txt:1" alone would describe a quarter of the work as the
// whole of it.
func (t Target) Where() string {
	switch len(t.Sites) {
	case 0:
		return "no pin site"
	case 1:
		return path.Clean(t.Sites[0].File) + fmt.Sprintf(":%d", t.Sites[0].Line)
	default:
		return fmt.Sprintf("%s:%d and %d more manifest%s",
			path.Clean(t.Sites[0].File), t.Sites[0].Line, len(t.Sites)-1, plural2(len(t.Sites)-1))
	}
}

func plural2(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
