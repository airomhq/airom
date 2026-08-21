package fix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pipConflict is what pip actually prints when the bumped pins do not resolve
// (captured from a real run, trimmed).
const pipConflict = `Collecting langchain==1.3.9
  Downloading langchain-1.3.9-py3-none-any.whl.metadata (6.4 kB)
Collecting langchain-community==0.3.27
INFO: pip is looking at multiple versions to determine which is compatible
ERROR: Cannot install -r requirements.txt (line 1) and -r requirements.txt (line 2) because these package versions have conflicting dependencies.

The conflict is caused by:
    langchain 1.3.9 depends on langchain-core<2.0.0 and >=1.4.6
    langchain-community 0.3.27 depends on langchain-core<1.0.0 and >=0.3.66

To fix this you could try to:
1. loosen the range of package versions you've specified

ERROR: ResolutionImpossible: for help visit https://pip.pypa.io/en/latest/topics/dependency-resolution/
`

// TestExcerptKeepsTheExplanation: the "Collecting …" preamble is noise and the
// "for help visit" footer is boilerplate; the clash is the answer.
func TestExcerptKeepsTheExplanation(t *testing.T) {
	got := excerpt(pipConflict, checkers["requirements.txt"].markers)
	joined := strings.Join(got, "\n")

	for _, want := range []string{
		"Cannot install",
		"The conflict is caused by:",
		"langchain 1.3.9 depends on langchain-core<2.0.0 and >=1.4.6",
		"langchain-community 0.3.27 depends on langchain-core<1.0.0 and >=0.3.66",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("excerpt dropped %q\ngot:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "Downloading") || strings.Contains(joined, "Collecting") {
		t.Errorf("excerpt kept the download preamble:\n%s", joined)
	}
	if strings.Contains(joined, "for help visit") {
		t.Errorf("excerpt kept the boilerplate footer:\n%s", joined)
	}
	if len(got) > maxDetailLines {
		t.Errorf("excerpt is %d lines, capped at %d", len(got), maxDetailLines)
	}
}

// TestExcerptFallsBackToTheTail when no marker is recognized — better to show
// the end of the output than nothing at all.
func TestExcerptFallsBackToTheTail(t *testing.T) {
	got := excerpt("alpha\nbeta\ngamma\n", []string{"NO-SUCH-MARKER"})
	if len(got) == 0 || got[len(got)-1] != "gamma" {
		t.Errorf("excerpt = %v, want the tail of the output", got)
	}
}

// TestUnknownManifestIsSkippedNotPassed. A manifest with no non-mutating
// resolver check must report "not checked", never a clean bill it never earned.
func TestUnknownManifestIsSkippedNotPassed(t *testing.T) {
	got := Verify(context.Background(), t.TempDir(), []string{"Cargo.toml"})
	if len(got) != 1 {
		t.Fatalf("Verify returned %d results, want 1", len(got))
	}
	if got[0].Status != VerifySkipped {
		t.Errorf("status = %q, want %q", got[0].Status, VerifySkipped)
	}
	if got[0].Reason == "" {
		t.Error("a skipped check must say why")
	}
	if Conflicted(got) {
		t.Error("a skipped check must not count as a conflict")
	}
}

// TestMissingToolIsSkippedNotAConflict: a fix session must not fail, or invent
// a finding, because the toolchain is absent.
func TestMissingToolIsSkippedNotAConflict(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("x==1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := checkers
	t.Cleanup(func() { checkers = saved })
	checkers = map[string]checker{"requirements.txt": {
		tool:  "definitely-not-a-real-tool",
		probe: []string{"airom-no-such-binary-xyz"},
		args:  func(string) []string { return []string{"airom-no-such-binary-xyz"} },
	}}

	got := Verify(context.Background(), root, []string{"requirements.txt"})
	if got[0].Status != VerifySkipped || !strings.Contains(got[0].Reason, "PATH") {
		t.Errorf("result = %+v, want skipped because the tool is absent", got[0])
	}
}

// TestInconclusiveOutputIsNotAConflict is the honesty guard on this whole file.
// pip on a PEP 668 system Python exits nonzero saying "externally managed",
// which has nothing to do with the pins — reporting it as a dependency conflict
// would be a fabricated finding.
func TestInconclusiveOutputIsNotAConflict(t *testing.T) {
	c := checkers["requirements.txt"]
	out := "error: externally-managed-environment\n× This environment is externally managed\n"
	if !containsAny(out, c.inconclusive) {
		t.Error("a PEP 668 refusal is not recognized as inconclusive")
	}
	if containsAny("ERROR: Cannot install -r requirements.txt", c.inconclusive) {
		t.Error("a real conflict was misread as inconclusive")
	}
}

// TestVerifyDeduplicatesManifests: three pins fixed in one requirements.txt is
// one resolver run, not three.
func TestVerifyDeduplicatesManifests(t *testing.T) {
	got := Verify(context.Background(), t.TempDir(),
		[]string{"Cargo.toml", "Cargo.toml", "pom.xml", "Cargo.toml"})
	if len(got) != 2 {
		t.Errorf("Verify ran %d checks, want one per distinct manifest (2)", len(got))
	}
}

func TestConflicted(t *testing.T) {
	if Conflicted([]VerifyResult{{Status: VerifyOK}, {Status: VerifySkipped}, {Status: VerifyErrored}}) {
		t.Error("Conflicted fired without a conflict")
	}
	if !Conflicted([]VerifyResult{{Status: VerifyOK}, {Status: VerifyConflict}}) {
		t.Error("Conflicted missed a conflict")
	}
}

// TestGoCheckDoesNotSwallowItsOwnErrors. `go list -m -e all` reports module
// errors in the OUTPUT and exits 0 — so with -e the check returns success for a
// version that does not exist and for a go.sum the bump invalidated, which are
// precisely the two failures docs/cve.md says it catches. Verified against the
// real toolchain: exit 0 with -e, exit 1 without.
func TestGoCheckDoesNotSwallowItsOwnErrors(t *testing.T) {
	argv := checkers["go.mod"].args("go.mod")
	for _, a := range argv {
		if a == "-e" {
			t.Fatalf("go check uses -e (%v): it would exit 0 on the errors it exists to find", argv)
		}
	}
}

// TestCancellationIsNotAConflict. A Ctrl-C during verification kills the
// resolver, which exits nonzero having said nothing about the pins. Reporting
// that as a conflict invents a finding — and then drives the revert prompt to
// propose undoing fixes that were fine.
func TestCancellationIsNotAConflict(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("x==1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := checkers
	t.Cleanup(func() { checkers = saved })
	checkers = map[string]checker{"requirements.txt": {
		tool:  "sleep",
		probe: []string{"sleep", "--version"},
		args:  func(string) []string { return []string{"sleep", "30"} },
	}}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	got := Verify(ctx, root, []string{"requirements.txt"})
	if got[0].Status == VerifyConflict {
		t.Error("an interrupted resolver was reported as a dependency conflict")
	}
	if got[0].Status != VerifyErrored {
		t.Errorf("status = %q, want %q", got[0].Status, VerifyErrored)
	}
	if Conflicted(got) {
		t.Error("Conflicted fired on an interrupted check")
	}
}

// TestAttributeSeparatesCauseFromInheritance. An unattributable conflict is
// dangerous in one specific way: it drives the offer to revert. A manifest that
// already did not resolve — a go.sum stale before anyone touched it, a peer
// clash the project has carried for months — would have real remediation rolled
// back to "solve" a problem the fix did not create and the revert does not fix.
func TestAttributeSeparatesCauseFromInheritance(t *testing.T) {
	before := []VerifyResult{
		{Manifest: "a.txt", Status: VerifyOK},
		{Manifest: "b.txt", Status: VerifyConflict},
		{Manifest: "c.txt", Status: VerifySkipped},
		{Manifest: "d.txt", Status: VerifyOK},
	}
	after := []VerifyResult{
		{Manifest: "a.txt", Status: VerifyConflict}, // the fix broke it
		{Manifest: "b.txt", Status: VerifyConflict}, // was already broken
		{Manifest: "c.txt", Status: VerifyConflict}, // no baseline verdict
		{Manifest: "d.txt", Status: VerifyOK},       // fine throughout
	}
	got := Attribute(before, after)

	want := map[string]Attribution{
		"a.txt": AttrIntroduced, "b.txt": AttrPreexisting, "c.txt": AttrUnknown,
	}
	if len(got) != len(want) {
		t.Fatalf("Attribute = %v, want %v", got, want)
	}
	for m, w := range want {
		if got[m] != w {
			t.Errorf("%s = %q, want %q", m, got[m], w)
		}
	}
	if _, ok := got["d.txt"]; ok {
		t.Error("a manifest with no conflict was attributed")
	}
	if !Introduced(got) {
		t.Error("Introduced missed a conflict the fix caused")
	}
}

// TestPreexistingConflictAloneDoesNotOfferRevert — the whole point of
// attribution.
func TestPreexistingConflictAloneDoesNotOfferRevert(t *testing.T) {
	attr := Attribute(
		[]VerifyResult{{Manifest: "a.txt", Status: VerifyConflict}},
		[]VerifyResult{{Manifest: "a.txt", Status: VerifyConflict}},
	)
	if Introduced(attr) {
		t.Error("a pre-existing conflict would have triggered the revert offer")
	}
}

// TestNoBaselineIsNotAnAllClear: with no before-fix run, a conflict is unknown,
// not innocent — and unknown still offers the revert, because the alternative is
// leaving a tree the resolver just refused without saying anything can be done.
func TestNoBaselineIsNotAnAllClear(t *testing.T) {
	attr := Attribute(nil, []VerifyResult{{Manifest: "a.txt", Status: VerifyConflict}})
	if attr["a.txt"] != AttrUnknown {
		t.Errorf("attribution = %q, want %q", attr["a.txt"], AttrUnknown)
	}
}

// TestManifestsSkipsWhatWillNotBeTouched — a baseline run on a manifest no fix
// will reach spends a resolver invocation on nothing.
func TestManifestsSkipsWhatWillNotBeTouched(t *testing.T) {
	got := Manifests([]Target{
		{Fixable: true, File: "requirements.txt"},
		{Fixable: true, File: "requirements.txt"}, // same file, one check
		{Fixable: false, File: "poetry.lock"},     // never edited
		{Fixable: true, File: ""},                 // no site
		{Fixable: true, File: "package.json"},
	})
	want := []string{"package.json", "requirements.txt"}
	if len(got) != len(want) {
		t.Fatalf("Manifests = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Manifests = %v, want %v", got, want)
		}
	}
}
