package fix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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

// ── Stub resolver ───────────────────────────────────────────────────────────
//
// A checker test needs two external commands: a probe that succeeds and a
// command that runs until it is killed. Borrowing system binaries for that
// couples the suite to whichever ones the runner ships — `sleep --version` is
// GNU coreutils and BSD sleep rejects it, so on macOS the probe failed, Verify
// short-circuited to "skipped", and the cancellation path the test exists to
// cover never ran. It failed green-adjacent: the assertion caught it, but the
// reason had nothing to do with the code under test.
//
// So the stub re-executes THIS test binary instead. It exists on every platform
// by construction, its flag grammar is the one the testing package defines, and
// there is no system tool left to differ.

const helperEnv = "AIROM_FIX_TEST_HELPER"

// helperArgv builds an argv that re-runs this binary as the named helper.
func helperArgv(t *testing.T, name string) []string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}
	return []string{self, "-test.run=^" + name + "$", "-test.count=1"}
}

// TestHelperExitsOK stands in for a resolver's availability probe: it returns
// immediately and successfully. Skipped during an ordinary run.
func TestHelperExitsOK(t *testing.T) {
	if os.Getenv(helperEnv) == "" {
		t.Skip("helper process; only meaningful when re-executed by a verification test")
	}
}

// helperStarted is the file TestHelperHangs drops in its working directory the
// moment it is running. A test waits for it before canceling, so cancellation
// lands during the stub resolver rather than during process startup.
//
// Sleeping a fixed "long enough" instead is what made this fragile: under -race
// the child binary takes longer to start than the delay allowed, so the CANCEL
// hit the availability probe and every assertion degraded to "skipped" — the
// same shape as the macOS failure, arrived at by timing rather than by flag
// grammar. A readiness signal has no margin to get wrong.
const helperStarted = ".airom-helper-started"

// TestHelperHangs stands in for a resolver still working when the user gives up.
// It announces itself, then outlives any cancellation the tests apply and is
// killed by the context; the sleep is a backstop, not the mechanism.
func TestHelperHangs(t *testing.T) {
	if os.Getenv(helperEnv) == "" {
		t.Skip("helper process; only meaningful when re-executed by a verification test")
	}
	if err := os.WriteFile(helperStarted, []byte("1"), 0o644); err != nil {
		t.Fatalf("signal readiness: %v", err)
	}
	time.Sleep(time.Minute)
}

// cancelOnceRunning cancels only after the stub resolver has signaled that it
// is running, so the test exercises the resolver path and not the probe.
func cancelOnceRunning(t *testing.T, dir string, cancel context.CancelFunc) {
	t.Helper()
	go func() {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(dir, helperStarted)); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel() // also fires on the deadline, so a stuck helper cannot hang the suite
	}()
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
	t.Setenv(helperEnv, "1") // inherited by both child processes
	saved := checkers
	t.Cleanup(func() { checkers = saved })
	checkers = map[string]checker{"requirements.txt": {
		tool:  "stub-resolver",
		probe: helperArgv(t, "TestHelperExitsOK"),
		args:  func(string) []string { return helperArgv(t, "TestHelperHangs") },
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelOnceRunning(t, root, cancel)

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
	// The probe must actually have run. A stub whose probe fails reports
	// "skipped" for a reason that has nothing to do with cancellation, which is
	// how the unportable `sleep --version` hid this path on macOS while still
	// looking like a real assertion failure.
	if got[0].Status == VerifySkipped {
		t.Fatalf("the stub probe did not run (%s); the cancellation path was never exercised", got[0].Reason)
	}
}

// TestTimeoutIsNotAConflict — the other way a resolver can be halted without
// ever giving a verdict. Exercised through run directly, so the assertion holds
// whether the deadline lands during startup or during the work.
func TestTimeoutIsNotAConflict(t *testing.T) {
	t.Setenv(helperEnv, "1")
	out, halted, err := run(context.Background(), t.TempDir(),
		helperArgv(t, "TestHelperHangs"), 200*time.Millisecond)
	if !halted {
		t.Fatalf("run did not report a halt on timeout: err=%v\n%s", err, out)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
	if r := haltReason("stub", err); !strings.Contains(r, "did not finish") {
		t.Errorf("haltReason = %q, want the timeout wording", r)
	}
	if r := haltReason("stub", context.Canceled); !strings.Contains(r, "interrupted") {
		t.Errorf("haltReason = %q, want the interruption wording", r)
	}
}

// TestProbeCancellationIsNotASkip. The availability probe runs under the
// caller's context too, so a Ctrl-C can land on IT rather than on the resolver.
// Reporting that as "the tool is not usable" is the same fabricated verdict as
// calling a killed resolver a conflict — nothing was learned about the tool or
// the pins, and the report has to say so.
func TestProbeCancellationIsNotASkip(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("x==1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(helperEnv, "1")
	saved := checkers
	t.Cleanup(func() { checkers = saved })
	checkers = map[string]checker{"requirements.txt": {
		tool:  "stub-resolver",
		probe: helperArgv(t, "TestHelperHangs"), // the probe is what hangs here
		args:  func(string) []string { return helperArgv(t, "TestHelperExitsOK") },
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelOnceRunning(t, root, cancel)

	got := Verify(ctx, root, []string{"requirements.txt"})
	if got[0].Status != VerifyErrored {
		t.Errorf("status = %q (%s), want %q", got[0].Status, got[0].Reason, VerifyErrored)
	}
	if got[0].Status == VerifySkipped {
		t.Error("an interrupted probe was reported as an unusable tool")
	}
	if Conflicted(got) {
		t.Error("Conflicted fired on an interrupted probe")
	}
}

// TestStubProbeIsPortable pins the property the macOS failure came down to: the
// stub's probe must succeed on whatever platform the suite is running on. If it
// ever stops doing so, every test built on the stub silently degrades to
// asserting "skipped" instead of what it was written to assert.
func TestStubProbeIsPortable(t *testing.T) {
	t.Setenv(helperEnv, "1")
	out, halted, err := run(context.Background(), t.TempDir(), helperArgv(t, "TestHelperExitsOK"), 30*time.Second)
	if err != nil || halted {
		t.Fatalf("the stub probe failed on %s/%s: err=%v halted=%v\n%s",
			runtime.GOOS, runtime.GOARCH, err, halted, out)
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
		{Fixable: true, Sites: []Site{{File: "requirements.txt", Line: 1}}},
		{Fixable: true, Sites: []Site{{File: "requirements.txt", Line: 1}}}, // same file, one check
		{Fixable: false, Sites: []Site{{File: "poetry.lock", Line: 1}}},     // never edited
		{Fixable: true, Sites: []Site{{File: "", Line: 1}}},                 // no site
		{Fixable: true, Sites: []Site{{File: "package.json", Line: 1}}},
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
