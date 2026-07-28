package airom

import (
	"path"
	"strings"
)

// IsTestPath reports whether a ROOT-RELATIVE path is test scaffolding rather
// than shipped code: a fixture, a test file, or a directory that holds them.
//
// The distinction matters because an AIBOM answers "what AI does this software
// use?", and a rule-pack fixture calling `model="gpt-4-32k"` is not an answer to
// that. AIROM's own repository is the extreme case: 179 of 185 components in a
// self-scan came only from `rules/models/testdata/*/usage.py` and `*_test.go`,
// so the document read as if the scanner itself depended on fifty hosted models.
// The same leak reaches users, because a scan root containing a vendored or
// cached Go module inherits THAT module's fixtures too.
//
// Root-relative is load-bearing. Paths are matched against the scan root, so
// pointing AIROM directly at a fixture directory (`airom fs ./testdata/rag-app`)
// reports it normally — the user asked about that tree, and nothing inside it is
// "the tests" of anything. Only paths that sit under a test directory *of the
// scanned project* are scoped out. Passing an absolute path here would classify
// by an accident of where the repo is checked out.
//
// Being wrong in the two directions costs differently. A false positive hides
// real production AI from the default view, so every pattern here is an
// unambiguous, language-standard test convention — never a substring match on
// "test", which would swallow `src/testimonials.py` or a `latest/` directory.
// A false negative merely leaves noise visible, which the reader can see and
// judge. When in doubt this returns false.
func IsTestPath(p string) bool {
	p = path.Clean(strings.TrimPrefix(strings.ReplaceAll(p, "\\", "/"), "./"))
	// A Windows drive-letter path survives the separator swap as "C:/repo/…",
	// which path.IsAbs does not recognize — it would sail past the guard below
	// and be classified by an accident of checkout location.
	if len(p) > 1 && p[1] == ':' {
		return false
	}
	if p == "" || p == "." || path.IsAbs(p) {
		// An absolute path cannot be judged against a scan root, and judging it
		// against the filesystem would make the verdict depend on checkout
		// location. Refuse rather than guess.
		return false
	}

	segs := strings.Split(p, "/")
	base := segs[len(segs)-1]
	for _, d := range segs[:len(segs)-1] {
		if isTestDir(strings.ToLower(d)) {
			return true
		}
	}
	// JUnit's convention is the only one that carries meaning in its CASE:
	// ChatTest.java is a test, Latest.java is not. Checked before folding,
	// because a case-insensitive "ends with test.java" is precisely the
	// substring match this package promises never to do — it would hide
	// Latest.java, Contest.java, and Greatest.java from every default view.
	if strings.HasSuffix(base, "Test.java") || strings.HasSuffix(base, "Tests.java") {
		return true
	}
	return isTestFile(strings.ToLower(base))
}

// isTestDir matches directory names that hold test material by convention in
// some ecosystem. Each entry is a name a build tool or test runner treats
// specially, not a name that merely reads as testy.
func isTestDir(d string) bool {
	switch d {
	case "testdata", // Go: the toolchain itself ignores this tree
		"__tests__",     // Jest
		"__mocks__",     // Jest
		"__fixtures__",  // Jest/JS convention
		"test", "tests", // near-universal
		"spec",     // RSpec, Jasmine
		"fixtures", // fixture data for any of the above
		"e2e", "integration-tests", "testutil", "testutils":
		return true
	}
	return false
}

// isTestFile matches file names that a test runner collects by convention.
func isTestFile(b string) bool {
	switch {
	case strings.HasSuffix(b, "_test.go"): // Go
		return true
	case b == "conftest.py": // pytest
		return true
	case strings.HasPrefix(b, "test_") && strings.HasSuffix(b, ".py"): // pytest
		return true
	case strings.HasSuffix(b, "_test.py"): // pytest (alternate)
		return true
	case strings.HasSuffix(b, "_spec.rb") || strings.HasSuffix(b, "_test.rb"): // RSpec / minitest
		return true
	case strings.HasSuffix(b, "_test.java"): // JUnit, snake spelling (ChatTest.java is handled case-sensitively)
		return true
	case strings.HasSuffix(b, "_test.rs"): // Rust
		return true
	}
	// JS/TS: foo.test.ts, foo.spec.tsx, foo.test.mjs …
	for _, ext := range []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"} {
		if strings.HasSuffix(b, ".test"+ext) || strings.HasSuffix(b, ".spec"+ext) {
			return true
		}
	}
	return false
}

// ProductionOccurrences returns the occurrences that are not test scaffolding,
// in a fresh slice — callers are typically writers, which must never mutate the
// document they were handed (P7).
//
// The attention surfaces need this on top of Component.TestOnly, because the two
// answer different questions. TestOnly asks "is this component only ever reached
// from tests?"; this asks "which of its sightings are production?". A package
// declared in requirements.txt and imported by three test files is a real
// dependency (TestOnly is false) whose test-file sightings still should not
// become code-scanning alerts or inflate an evidence count.
func ProductionOccurrences(occs []Occurrence) []Occurrence {
	out := make([]Occurrence, 0, len(occs))
	for _, o := range occs {
		if !IsTestPath(o.Location.Path) {
			out = append(out, o)
		}
	}
	return out
}

// OccurrencesAreTestOnly reports whether EVERY occurrence sits in test
// scaffolding — the condition the assembler uses to set Component.TestOnly, and
// so the condition under which a component is scoped out of the default view and
// marked `scope: excluded` in CycloneDX.
//
// All, not any: a model called from both `src/chat.py` and `tests/test_chat.py`
// is production AI that happens to be tested. Scoping it out because one
// occurrence is a test would hide exactly the thing the document exists to
// report. No occurrences at all (the synthesized root application) is never
// test-only — absence of evidence is not evidence of tests.
func OccurrencesAreTestOnly(occs []Occurrence) bool {
	if len(occs) == 0 {
		return false
	}
	for _, o := range occs {
		if !IsTestPath(o.Location.Path) {
			return false
		}
	}
	return true
}
