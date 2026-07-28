package airom_test

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestIsTestPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
		why  string
	}{
		// The paths that made AIROM's own self-scan 97% noise.
		{"rules/models/testdata/groq/usage.py", true, "Go's own ignored-tree convention"},
		{"internal/ruleengine/ruleengine_test.go", true, "Go test file"},
		{"internal/app/eol_test.go", true, "Go test file"},
		// A cached/vendored module drags its fixtures into a user's scan.
		{"third_party/airom@v0.2.0/internal/app/eol_test.go", true, "vendored module's tests"},

		// Other ecosystems' standard layouts.
		{"tests/test_chat.py", true, "pytest dir + file"},
		{"test_rag.py", true, "pytest file at root"},
		{"conftest.py", true, "pytest config"},
		{"src/__tests__/chat.js", true, "Jest"},
		{"src/chat.test.ts", true, "Jest/Vitest suffix"},
		{"src/chat.spec.tsx", true, "Jasmine/Angular suffix"},
		{"spec/models/chat_spec.rb", true, "RSpec"},
		{"src/test/java/com/x/ChatTest.java", true, "Maven layout"},
		{"src/main/java/com/x/ChatTest.java", true, "JUnit names the file, not just the dir"},
		{"src/main/java/com/x/ChatTests.java", true, "JUnit 5 plural"},
		{"e2e/checkout.spec.js", true, "e2e dir"},

		// ── The expensive mistakes: production code that merely reads testy ──
		{"src/testimonials.py", false, "substring 'test' is not a test file"},
		{"models/latest/config.json", false, "'latest' contains 'test'"},
		{"src/contest/scoring.py", false, "'contest' contains 'test'"},
		{"app/protest_classifier.py", false, "'protest' contains 'test'"},
		{"src/attestation/verify.go", false, "attestation is a real AIROM concept"},
		// The JUnit rule is the one convention that depends on CASE. Folding the
		// basename first turned it into a substring match that hid three ordinary
		// production files — the exact failure this package promises to avoid.
		{"src/main/java/com/x/Latest.java", false, "Latest.java is not a test"},
		{"src/main/java/com/x/Contest.java", false, "Contest.java is not a test"},
		{"src/main/java/com/x/Greatest.java", false, "Greatest.java is not a test"},
		{"src/main/java/com/x/protest.java", false, "lowercased spelling must not match either"},
		{"pkg/airom/testscope.go", false, "a file ABOUT tests is not a test"},
		{"specs/openapi.yaml", false, "'specs' is not the RSpec 'spec' dir"},

		// Ordinary production paths.
		{"main.py", false, ""},
		{"src/rag.py", false, ""},
		{"internal/app/scan.go", false, ""},

		// Degenerate input.
		{"", false, "empty"},
		{".", false, "root itself"},
		{"/abs/testdata/x.py", false, "absolute paths cannot be judged against a scan root"},
		{`C:\repo\testdata\x.py`, false, "a Windows absolute path is absolute too"},
	}
	for _, tc := range cases {
		if got := airom.IsTestPath(tc.path); got != tc.want {
			t.Errorf("IsTestPath(%q) = %v, want %v — %s", tc.path, got, tc.want, tc.why)
		}
	}
}

// TestIsTestPathNormalizes: detectors on Windows and detectors that emit
// "./foo" must classify the same as everyone else, or the verdict would depend
// on which detector found the file.
func TestIsTestPathNormalizes(t *testing.T) {
	for _, p := range []string{
		`internal\app\eol_test.go`,
		"./internal/app/eol_test.go",
		"internal/./app/eol_test.go",
		"TESTDATA/usage.py",
		"src/Chat.Test.ts",
	} {
		if !airom.IsTestPath(p) {
			t.Errorf("IsTestPath(%q) = false, want true after normalization", p)
		}
	}
}

// TestOccurrencesAreTestOnlyRequiresAll is the rule that keeps the feature from
// hiding real findings: a model reached from production code AND exercised by a
// test is production AI. Scoping it out would suppress exactly what the document
// exists to report.
func TestOccurrencesAreTestOnlyRequiresAll(t *testing.T) {
	at := func(paths ...string) []airom.Occurrence {
		occs := make([]airom.Occurrence, 0, len(paths))
		for _, p := range paths {
			occs = append(occs, airom.Occurrence{Location: airom.Location{Path: p}})
		}
		return occs
	}
	cases := []struct {
		name string
		occs []airom.Occurrence
		want bool
	}{
		{"all tests", at("tests/test_a.py", "conftest.py"), true},
		{"mixed — production wins", at("tests/test_a.py", "src/chat.py"), false},
		{"one production occurrence", at("src/chat.py"), false},
		{"no evidence is not test evidence", nil, false},
	}
	for _, tc := range cases {
		if got := airom.OccurrencesAreTestOnly(tc.occs); got != tc.want {
			t.Errorf("%s: OccurrencesAreTestOnly = %v, want %v", tc.name, got, tc.want)
		}
	}
}
