package fix

import (
	"strings"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

// comp builds a vulnerable package component with one manifest occurrence.
func comp(name, version, purl, detector, path string, line int, snippet string, vulns ...airom.Vulnerability) airom.Component {
	return airom.Component{
		Kind:            airom.KindLibrary,
		Name:            name,
		Version:         airom.KnownString(version),
		PURL:            purl,
		Vulnerabilities: vulns,
		Evidence: airom.Evidence{Occurrences: []airom.Occurrence{{
			Location:   airom.Location{Path: path, Line: line},
			DetectorID: detector,
			Confidence: 0.95,
			Snippet:    snippet,
		}}},
	}
}

func vuln(id string, sev airom.VulnSeverity, fixed string) airom.Vulnerability {
	return airom.Vulnerability{ID: id, Severity: sev, Fixed: fixed, Source: "osv.dev"}
}

func inventory(cs ...airom.Component) *airom.Inventory {
	return &airom.Inventory{Components: cs}
}

// TestPlanPicksHighestFixed asserts the remediation is the single bump that
// clears every advisory, not the first one an advisory happened to name.
func TestPlanPicksHighestFixed(t *testing.T) {
	inv := inventory(comp("langchain", "0.0.310", "pkg:pypi/langchain@0.0.310",
		"manifest/pypi-requirements", "requirements.txt", 1, "langchain==0.0.310",
		vuln("CVE-1", airom.VulnLow, "0.1.0"),
		vuln("CVE-2", airom.VulnCritical, "0.2.4"),
		vuln("CVE-3", airom.VulnMedium, "0.0.339"),
	))
	got := Plan(inv, false)
	if len(got) != 1 {
		t.Fatalf("Plan returned %d targets, want 1", len(got))
	}
	tg := got[0]
	if tg.Fixed != "0.2.4" {
		t.Errorf("Fixed = %q, want the highest named fix 0.2.4", tg.Fixed)
	}
	if tg.Severity != airom.VulnCritical {
		t.Errorf("Severity = %q, want the most severe bucket present", tg.Severity)
	}
	if !tg.Fixable || tg.Sites[0].File != "requirements.txt" || tg.Sites[0].Line != 1 {
		t.Errorf("pin site = %v %v, want fixable requirements.txt:1", tg.Fixable, tg.Sites)
	}
	if tg.Ecosystem != "pypi" {
		t.Errorf("Ecosystem = %q, want pypi", tg.Ecosystem)
	}
	// Advisories must be ordered most-severe-first, like every other CVE surface.
	if tg.Vulns[0].ID != "CVE-2" {
		t.Errorf("first advisory = %q, want the critical one", tg.Vulns[0].ID)
	}
}

// TestPlanSkipsFixesAtOrBelowInstalled guards the case that makes a "fix"
// actively harmful: an advisory whose fixed version is older than what is
// installed would downgrade the package if taken literally.
func TestPlanSkipsFixesAtOrBelowInstalled(t *testing.T) {
	inv := inventory(comp("pkg", "2.0.0", "pkg:pypi/pkg@2.0.0",
		"manifest/pypi-requirements", "requirements.txt", 1, "pkg==2.0.0",
		vuln("CVE-OLD", airom.VulnHigh, "1.5.0"),
	))
	if got := Plan(inv, false); len(got) != 0 {
		t.Fatalf("Plan returned %d targets, want none: 1.5.0 is a downgrade from 2.0.0", len(got))
	}
}

// TestPlanIgnoresUnorderableFixedVersions: an advisory that "fixes" at a git
// commit names nothing we can prove is an upgrade.
func TestPlanIgnoresUnorderableFixedVersions(t *testing.T) {
	inv := inventory(comp("pkg", "1.0.0", "pkg:pypi/pkg@1.0.0",
		"manifest/pypi-requirements", "requirements.txt", 1, "pkg==1.0.0",
		vuln("CVE-GIT", airom.VulnHigh, "a1b2c3d4e5f6"),
		vuln("CVE-REAL", airom.VulnLow, "1.0.4"),
	))
	got := Plan(inv, false)
	if len(got) != 1 || got[0].Fixed != "1.0.4" {
		t.Fatalf("Plan = %+v, want a single target fixing at 1.0.4", got)
	}
}

func TestCrossesMajor(t *testing.T) {
	cases := []struct {
		current, fixed string
		want           bool
	}{
		{"4.30.0", "4.53.0", false},
		{"4.30.0", "5.5.0", true},
		{"0.0.310", "0.0.339", false},
		{"0.0.310", "1.3.9", true},
		{"0.2.4", "0.3.27", true}, // pre-1.0: the leading nonzero is the major
		{"0.2.4", "0.2.9", false}, // same 0.2 line
		{"1.0.0", "1.0.1", false},
		{"deadbeef", "1.0.0", false}, // unorderable: claim nothing
	}
	for _, c := range cases {
		if got := crossesMajor(c.current, c.fixed); got != c.want {
			t.Errorf("crossesMajor(%q, %q) = %v, want %v", c.current, c.fixed, got, c.want)
		}
	}
}

// TestPlanRefusesDerivedSources is the core safety property: a lockfile records
// a resolution, and rewriting one forges a decision no resolver made. The
// finding must still be REPORTED, with a reason.
func TestPlanRefusesDerivedSources(t *testing.T) {
	inv := inventory(comp("pkg", "1.0.0", "pkg:pypi/pkg@1.0.0",
		"manifest/pypi-lock", "poetry.lock", 42, `name = "pkg"`,
		vuln("CVE-1", airom.VulnHigh, "1.0.4"),
	))
	got := Plan(inv, false)
	if len(got) != 1 {
		t.Fatalf("Plan returned %d targets, want the finding reported anyway", len(got))
	}
	if got[0].Fixable {
		t.Error("a lockfile sighting must not be marked fixable")
	}
	if got[0].Reason == "" {
		t.Error("an unfixable target must carry a reason")
	}
}

// TestPlanPrefersManifestOverLockfile: a package seen in both must be fixed at
// the manifest that declares it.
func TestPlanPrefersManifestOverLockfile(t *testing.T) {
	c := comp("pkg", "1.0.0", "pkg:pypi/pkg@1.0.0",
		"manifest/pypi-lock", "poetry.lock", 42, `name = "pkg"`,
		vuln("CVE-1", airom.VulnHigh, "1.0.4"))
	c.Evidence.Occurrences = append(c.Evidence.Occurrences, airom.Occurrence{
		Location:   airom.Location{Path: "pyproject.toml", Line: 7},
		DetectorID: "manifest/pypi-pyproject",
		Confidence: 0.9,
		Snippet:    `pkg = "1.0.0"`,
	})
	got := Plan(inventory(c), false)
	if len(got) != 1 || !got[0].Fixable || got[0].Sites[0].File != "pyproject.toml" {
		t.Fatalf("Plan = %+v, want the fix targeted at pyproject.toml", got)
	}
}

// TestPlanScopesTestOnly mirrors the table: a component seen only in test
// scaffolding is off the attention surfaces unless the user asks for it.
func TestPlanScopesTestOnly(t *testing.T) {
	c := comp("pkg", "1.0.0", "pkg:pypi/pkg@1.0.0",
		"manifest/pypi-requirements", "tests/requirements.txt", 1, "pkg==1.0.0",
		vuln("CVE-1", airom.VulnHigh, "1.0.4"))
	c.TestOnly = true
	if got := Plan(inventory(c), false); len(got) != 0 {
		t.Errorf("test-only component surfaced without --include-tests: %+v", got)
	}
	if got := Plan(inventory(c), true); len(got) != 1 {
		t.Errorf("test-only component hidden despite --include-tests: %+v", got)
	}
}

// TestPlanSkipsComponentsWithNoDefiniteVersion: a declared range never matched
// an advisory in the first place, so there is nothing to bump.
func TestPlanSkipsComponentsWithNoDefiniteVersion(t *testing.T) {
	c := comp("pkg", "1.0.0", "pkg:pypi/pkg", "manifest/npm", "package.json", 4,
		`"pkg": "^1.0.0"`, vuln("CVE-1", airom.VulnHigh, "1.0.4"))
	c.Version = airom.OptString{} // absent
	if got := Plan(inventory(c), false); len(got) != 0 {
		t.Errorf("a component with no resolved version produced a fix: %+v", got)
	}
}

// TestPlanOrdersBySeverity keeps the fix table's first row the one a reviewer
// would reach for first.
func TestPlanOrdersBySeverity(t *testing.T) {
	inv := inventory(
		comp("low-pkg", "1.0.0", "pkg:pypi/low-pkg@1.0.0", "manifest/pypi-requirements",
			"requirements.txt", 1, "low-pkg==1.0.0", vuln("CVE-L", airom.VulnLow, "1.1.0")),
		comp("crit-pkg", "1.0.0", "pkg:pypi/crit-pkg@1.0.0", "manifest/pypi-requirements",
			"requirements.txt", 2, "crit-pkg==1.0.0", vuln("CVE-C", airom.VulnCritical, "1.1.0")),
	)
	got := Plan(inv, false)
	if len(got) != 2 || got[0].Package != "crit-pkg" {
		t.Fatalf("Plan order = %v, want the critical package first", got)
	}
}

// TestRangeDeclarationIsNotOfferedAsFixable. The assembler resolves Version from
// a lockfile while the manifest declares a range, so Current is a version the
// manifest never spells. Offering [ Fix ] there produces a button that always
// refuses, with an error blaming the user's file for something it never said —
// and re-scanning reproduces it forever.
func TestRangeDeclarationIsNotOfferedAsFixable(t *testing.T) {
	cases := []struct{ name, detector, path, snippet string }{
		{"npm caret range", "manifest/npm", "package.json", `"openai": "^4.0.0",`},
		{"requirements lower bound", "manifest/pypi-requirements", "requirements.txt", "openai>=4.0.0"},
		{"pyproject compatible release", "manifest/pypi-pyproject", "pyproject.toml", `openai = "~4.0"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := inventory(comp("openai", "4.2.1", "pkg:pypi/openai@4.2.1",
				c.detector, c.path, 4, c.snippet,
				vuln("CVE-1", airom.VulnHigh, "4.104.0"),
			))
			got := Plan(inv, false)
			if len(got) != 1 {
				t.Fatalf("Plan returned %d targets, want the finding reported", len(got))
			}
			if got[0].Fixable {
				t.Error("a range declaration was offered as fixable; the button would always refuse")
			}
			if !strings.Contains(got[0].Reason, "range") {
				t.Errorf("Reason = %q, want it to explain the range", got[0].Reason)
			}
		})
	}
}

// TestExactPinIsStillFixable — the range check must not reject a real pin.
func TestExactPinIsStillFixable(t *testing.T) {
	inv := inventory(comp("openai", "4.2.1", "pkg:pypi/openai@4.2.1",
		"manifest/npm", "package.json", 4, `"openai": "4.2.1",`,
		vuln("CVE-1", airom.VulnHigh, "4.104.0"),
	))
	got := Plan(inv, false)
	if len(got) != 1 || !got[0].Fixable {
		t.Fatalf("Plan = %+v, want an exact pin to stay fixable", got)
	}
}

// TestMavenAndFrozenCarryTheirOwnReason. The Maven detector records the
// <dependency> open-tag line, which holds neither artifactId nor version; a
// PyInstaller binary holds no pin at all. Both must say so rather than fail
// later with "your file changed".
func TestMavenAndFrozenCarryTheirOwnReason(t *testing.T) {
	cases := []struct{ name, detector, path, snippet, want string }{
		{"maven", "manifest/maven", "pom.xml", "        <dependency>", "another line"},
		{"pyinstaller", "frozen/pyinstaller", "dist/app", "", "rebuild"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Plan(inventory(comp("some.group:artifact", "1.0.0", "pkg:maven/some.group/artifact@1.0.0",
				c.detector, c.path, 12, c.snippet,
				vuln("CVE-1", airom.VulnHigh, "1.1.0"))), false)
			if len(got) != 1 {
				t.Fatalf("Plan returned %d targets, want the finding reported", len(got))
			}
			if got[0].Fixable {
				t.Errorf("%s was offered as fixable", c.name)
			}
			if !strings.Contains(got[0].Reason, c.want) {
				t.Errorf("Reason = %q, want it to mention %q", got[0].Reason, c.want)
			}
		})
	}
}

// TestGradleStaysFixable: unlike Maven, the Gradle detector records the line
// carrying the whole group:artifact:version coordinate, so it has a pin to
// rewrite.
func TestGradleStaysFixable(t *testing.T) {
	got := Plan(inventory(comp("langchain4j", "0.30.0", "pkg:maven/dev.langchain4j/langchain4j@0.30.0",
		"manifest/gradle", "build.gradle", 12,
		`    implementation 'dev.langchain4j:langchain4j:0.30.0'`,
		vuln("CVE-1", airom.VulnHigh, "0.31.0"))), false)
	if len(got) != 1 || !got[0].Fixable {
		t.Fatalf("Plan = %+v, want the gradle coordinate to stay fixable", got)
	}
}

func TestSummarize(t *testing.T) {
	got := Summarize([]Target{
		{Fixable: true, Vulns: make([]Vuln, 3)},
		{Fixable: true, Vulns: make([]Vuln, 1)},
		{Fixable: false, Vulns: make([]Vuln, 2)},
	})
	want := Summary{Fixable: 2, Unfixable: 1, Vulns: 6}
	if got != want {
		t.Errorf("Summarize = %+v, want %+v", got, want)
	}
	if zero := Summarize(nil); zero != (Summary{}) {
		t.Errorf("Summarize(nil) = %+v, want the zero Summary", zero)
	}
}

// TestTargetString is the line a --fix-all report and the no-terminal fallback
// print, so its shape is user-facing: the versions, the advisory count, the
// severity, the site, and the major-bump warning when there is one.
func TestTargetString(t *testing.T) {
	base := Target{
		Package: "langchain", Current: "0.0.310", Fixed: "0.2.4",
		Severity: airom.VulnCritical, Sites: []Site{{File: "./requirements.txt", Line: 1}},
		Vulns: make([]Vuln, 12),
	}
	got := base.String()
	for _, want := range []string{
		"langchain 0.0.310 -> 0.2.4", "12 advisories", "CRITICAL", "requirements.txt:1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
	if strings.Contains(got, "major") {
		t.Errorf("String() = %q, claimed a major bump on a Target without one", got)
	}

	major := base
	major.Major = true
	if !strings.Contains(major.String(), "[major bump]") {
		t.Errorf("String() = %q, want the major-bump marker", major.String())
	}

	// One advisory is singular — the report reads as prose, not as a template.
	one := base
	one.Vulns = make([]Vuln, 1)
	if !strings.Contains(one.String(), "1 advisory") || strings.Contains(one.String(), "advisories") {
		t.Errorf("String() = %q, want the singular form", one.String())
	}
}

// TestPlanCollectsEveryPinSite: assembly merges sightings of the same package
// into one component, so the plan has to carry every manifest that pins it or
// the fix silently covers a fraction of the exposure.
func TestPlanCollectsEveryPinSite(t *testing.T) {
	c := comp("langchain", "0.2.16", "pkg:pypi/langchain@0.2.16",
		"manifest/pypi-requirements", "worker/requirements.txt", 1, "langchain==0.2.16",
		vuln("CVE-1", airom.VulnHigh, "1.3.9"))
	for _, extra := range []struct {
		path string
		line int
	}{{"api/requirements.txt", 3}, {"requirements.txt", 2}} {
		c.Evidence.Occurrences = append(c.Evidence.Occurrences, airom.Occurrence{
			Location:   airom.Location{Path: extra.path, Line: extra.line},
			DetectorID: "manifest/pypi-requirements",
			Confidence: 0.95,
			Snippet:    "langchain==0.2.16",
		})
	}

	got := Plan(inventory(c), false)
	if len(got) != 1 {
		t.Fatalf("Plan returned %d targets, want 1", len(got))
	}
	if len(got[0].Sites) != 3 {
		t.Fatalf("Sites = %v, want all three manifests", got[0].Sites)
	}
	// Deterministic order (P7), whatever order detection produced.
	want := []string{"api/requirements.txt:3", "requirements.txt:2", "worker/requirements.txt:1"}
	for i, w := range want {
		if got[0].Sites[i].String() != w {
			t.Errorf("Sites[%d] = %s, want %s", i, got[0].Sites[i], w)
		}
	}
	// The one-line summary must not describe a third of the work as all of it.
	if !strings.Contains(got[0].Where(), "2 more manifests") {
		t.Errorf("Where() = %q, want it to count the other manifests", got[0].Where())
	}
}
