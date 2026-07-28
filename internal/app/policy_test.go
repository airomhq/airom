package app

import (
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func TestParsePolicyValid(t *testing.T) {
	cases := []struct {
		expr     string
		wantAnys int   // number of OR clauses
		wantLens []int // terms per clause
	}{
		{"hosted-llm", 1, []int{1}},
		{"pickle-risk", 1, []int{1}},
		{"cve", 1, []int{1}},
		{"cve:high", 1, []int{1}},
		{"cve:critical&framework", 1, []int{2}},
		{"eol", 1, []int{1}},
		{"eol:retired", 1, []int{1}},
		{"eol:deprecated", 1, []int{1}},
		{"eol:before:2027-01-01", 1, []int{1}},
		{"eol:retired|cve:critical", 2, []int{1, 1}},
		{"hosted-llm&confidence>=0.9", 1, []int{2}},
		{"  hosted-llm & confidence >= 0.9 ", 1, []int{2}},
		{"local-model-file|hosted-llm&confidence>=0.8", 2, []int{1, 2}},
		{"prompt|dataset|framework", 3, []int{1, 1, 1}},
		{"confidence<0.5", 1, []int{1}},
		{"confidence=1", 1, []int{1}},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			p, err := ParsePolicy(tc.expr)
			if err != nil {
				t.Fatalf("ParsePolicy(%q) error: %v", tc.expr, err)
			}
			if got := len(p.anyOf); got != tc.wantAnys {
				t.Fatalf("clauses = %d, want %d", got, tc.wantAnys)
			}
			for i, want := range tc.wantLens {
				if got := len(p.anyOf[i].terms); got != want {
					t.Errorf("clause %d terms = %d, want %d", i, got, want)
				}
			}
			if p.String() != strings.TrimSpace(tc.expr) {
				t.Errorf("String() = %q, want trimmed input", p.String())
			}
		})
	}
}

func TestParsePolicyInvalid(t *testing.T) {
	for _, expr := range []string{
		"",
		"   ",
		"&",
		"hosted-llm&",
		"|hosted-llm",
		"a||b",
		"confidence>>1",
		"confidence>=1.5",
		"confidence>=-0.1",
		"confidence>=",
		"confidence", // bare reserved word: almost certainly a typo'd comparison
		"Hosted-LLM", // uppercase not allowed
		"has space",
		"confidence0.9",
		"cve:bogus",  // unknown cve severity
		"cve:severe", // unknown cve severity
		"cve:pickle", // cve takes a severity, not a slug
		// A gate exists to catch findings: "supported" and "unknown" are not
		// findings, and a gate on "unknown" would fire on every uncurated model.
		"eol:supported",
		"eol:unknown",
		"eol:sunsetting",        // not a state
		"eol:before:soon",       // not a date
		"eol:before:2027-13-45", // not a real date
		"eol:before:2027/01/01", // wrong date form
		"eol:2027-01-01",        // date without the before: keyword
	} {
		t.Run(expr, func(t *testing.T) {
			if _, err := ParsePolicy(expr); err == nil {
				t.Fatalf("ParsePolicy(%q): want error, got nil", expr)
			}
		})
	}
}

func TestMatchAny(t *testing.T) {
	p := MatchAny()
	if p == nil || len(p.anyOf) != 1 {
		t.Fatalf("MatchAny misshapen: %+v", p)
	}
}

// TestReferencesCVE pins the guard that config validation relies on to reject
// gating on CVEs that were never fetched (--fail-on cve without --cve).
func TestReferencesCVE(t *testing.T) {
	cases := []struct {
		expr string
		want bool
	}{
		{"cve", true},
		{"cve:high", true},
		{"hosted-llm|cve:critical", true},
		{"framework&cve", true},
		{"hosted-llm", false},
		{"risk:high", false},
		{"pickle-risk", false},
		{"eol:retired", false},
	}
	for _, tc := range cases {
		p, err := ParsePolicy(tc.expr)
		if err != nil {
			t.Fatalf("ParsePolicy(%q): %v", tc.expr, err)
		}
		if got := p.ReferencesCVE(); got != tc.want {
			t.Errorf("ReferencesCVE(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
	// A nil policy references nothing.
	var nilPolicy *Policy
	if nilPolicy.ReferencesCVE() {
		t.Error("nil policy must not reference CVE")
	}
}

// TestReferencesEOL pins the guard config validation uses to reject gating on
// an overlay that was turned off — a gate that could only ever pass.
func TestReferencesEOL(t *testing.T) {
	cases := []struct {
		expr string
		want bool
	}{
		{"eol", true},
		{"eol:retired", true},
		{"eol:before:2027-01-01", true},
		{"hosted-llm|eol:deprecated", true},
		{"framework&eol", true},
		{"hosted-llm", false},
		{"cve:high", false},
		{"risk:high", false},
	}
	for _, tc := range cases {
		p, err := ParsePolicy(tc.expr)
		if err != nil {
			t.Fatalf("ParsePolicy(%q): %v", tc.expr, err)
		}
		if got := p.ReferencesEOL(); got != tc.want {
			t.Errorf("ReferencesEOL(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
	var nilPolicy *Policy
	if nilPolicy.ReferencesEOL() {
		t.Error("nil policy must not reference EOL")
	}
}

// TestEOLTermMatches pins the gate semantics that decide whether a build fails:
// the state threshold, the date form, and the rule that an absent record is
// never a finding.
func TestEOLTermMatches(t *testing.T) {
	day := func(y, m, d int) *airom.Date {
		v := airom.Date{Year: y, Month: time.Month(m), Day: d}
		return &v
	}
	comp := func(lc *airom.Lifecycle) *airom.Component {
		return &airom.Component{Kind: airom.KindHostedLLM, Name: "m", EOL: lc}
	}
	retired := comp(&airom.Lifecycle{State: airom.EOLRetired, Shutdown: day(2025, 6, 6)})
	deprecated := comp(&airom.Lifecycle{State: airom.EOLDeprecated, Shutdown: day(2026, 10, 23)})
	undated := comp(&airom.Lifecycle{State: airom.EOLDeprecated}) // announced, date TBA
	supported := comp(&airom.Lifecycle{State: airom.EOLSupported})
	none := comp(nil) // uncurated: no claim

	cases := []struct {
		sel  string
		c    *airom.Component
		want bool
	}{
		// Bare "eol" = any announced retirement, and nothing else.
		{"eol", retired, true},
		{"eol", deprecated, true},
		{"eol", undated, true},
		{"eol", supported, false},
		{"eol", none, false},

		// Exact-ish state selectors, with the same threshold semantics as cve:.
		{"eol:retired", retired, true},
		{"eol:retired", deprecated, false},
		{"eol:deprecated", deprecated, true},
		{"eol:deprecated", retired, true}, // threshold: retired is worse
		{"eol:deprecated", supported, false},

		// The planning gate: does anything die before my next release train?
		{"eol:before:2027-01-01", deprecated, true},  // shuts down 2026-10-23
		{"eol:before:2026-01-01", deprecated, false}, // not before that
		{"eol:before:2026-01-01", retired, true},     // already gone, so yes
		// The boundary the gate exists for: the train leaves ON the shutdown
		// day. DeriveEOLState calls that day retired, so the gate must agree —
		// an exclusive cutoff here would pass a build shipping a dead model.
		{"eol:before:2026-10-23", deprecated, true},
		{"eol:before:2026-10-22", deprecated, false},
		// An undated deprecation cannot answer "before X" — claiming it would
		// invent a deadline the provider never announced.
		{"eol:before:2099-01-01", undated, false},
		// …but an undated RETIRED record is already gone, so it is before any
		// date. Only the undated deprecation is unanswerable.
		{"eol:before:2099-01-01", comp(&airom.Lifecycle{State: airom.EOLRetired}), true},
		{"eol:before:2099-01-01", supported, false},
		{"eol:before:2099-01-01", none, false},
	}
	for _, tc := range cases {
		if got := eolTermMatches(tc.sel, tc.c); got != tc.want {
			state := "nil"
			if tc.c.EOL != nil {
				state = string(tc.c.EOL.State)
			}
			t.Errorf("eolTermMatches(%q, state=%s) = %v, want %v", tc.sel, state, got, tc.want)
		}
	}
}

// TestParsePolicyRejectsUnknownIdentifiers pins the worst defect this gate ever
// had: an unknown term parsed happily and then never matched, so a one-character
// typo turned a CI gate into a permanent, silent pass.
func TestParsePolicyRejectsUnknownIdentifiers(t *testing.T) {
	for _, expr := range []string{
		"hosted-llmm",           // the typo that started it
		"totalnonsense",         //
		"rules",                 // a detector tag: never matchable here
		"application",           // real kind, but Matches skips the scan root
		"hosted-llm|bogus",      // unknown in the second clause
		"hosted-llm&bogus",      // unknown in a conjunction
		"bogus&confidence>=0.9", //
	} {
		if _, err := ParsePolicy(expr); err == nil {
			t.Errorf("ParsePolicy(%q) = nil error; an unmatched term must fail loudly, not pass forever", expr)
		}
	}
}

// TestConfidenceIsAReservedWordNotAReservedPrefix keeps the distinction the
// grammar draws: "confidencex" is a malformed identifier, not a malformed
// comparison, and its error must say so. (Both are rejected now — the point is
// WHICH diagnostic the user gets.)
func TestConfidenceIsAReservedWordNotAReservedPrefix(t *testing.T) {
	cases := []struct{ expr, wantErrSubstr string }{
		{"confidencex", "unknown term"},
		{"confidence-risk", "unknown term"},
		{"confidence", "bad confidence comparison"},
		{"confidence>=abc", "bad confidence comparison"},
	}
	for _, c := range cases {
		_, err := ParsePolicy(c.expr)
		if err == nil {
			t.Errorf("ParsePolicy(%q) = nil error, want %q", c.expr, c.wantErrSubstr)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErrSubstr) {
			t.Errorf("ParsePolicy(%q) error = %q, want it to mention %q", c.expr, err, c.wantErrSubstr)
		}
	}
}

// TestParsePolicyAcceptsEveryMatchableIdentifier: the validation must not
// over-reach. Every kind termMatches can match has to remain expressible.
func TestParsePolicyAcceptsEveryMatchableIdentifier(t *testing.T) {
	for _, k := range airom.Kinds() {
		if k == airom.KindApplication {
			continue // by design: Matches skips the scan root
		}
		if _, err := ParsePolicy(string(k)); err != nil {
			t.Errorf("ParsePolicy(%q): %v; every matchable kind must be gate-able", k, err)
		}
	}
	for _, expr := range []string{
		"pickle-risk",
		"confidence>=0.9",
		"hosted-llm&confidence>=0.9",
		"local-model-file|hosted-llm&confidence>=0.8",
	} {
		if _, err := ParsePolicy(expr); err != nil {
			t.Errorf("ParsePolicy(%q): %v", expr, err)
		}
	}
}
