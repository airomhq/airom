package fix

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPickInstallerFollowsTheLockfileInTheProject. npm, yarn, and pnpm all
// install a package.json, and picking the wrong one writes a second lockfile
// beside the real one — leaving the project with two disagreeing resolutions.
// The lockfile already present is the reliable signal for which manager this
// project actually uses.
func TestPickInstallerFollowsTheLockfileInTheProject(t *testing.T) {
	cases := []struct{ lock, want string }{
		{"pnpm-lock.yaml", "pnpm"},
		{"yarn.lock", "yarn"},
		{"package-lock.json", "npm"},
		{"", "npm"}, // no lockfile at all: npm is the default
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, "package.json", "{}")
			if c.lock != "" {
				write(t, dir, c.lock, "{}")
			}
			got, ok := pickInstaller("package.json", dir)
			if !ok || got.tool != c.want {
				t.Errorf("pickInstaller = %q (ok=%v), want %q", got.tool, ok, c.want)
			}
		})
	}
}

// TestNoInstallerIsSkippedNotFailed. A manifest with no wired package manager
// has to say "not installed", never report a failure that did not happen.
func TestNoInstallerIsSkippedNotFailed(t *testing.T) {
	got := Install(context.Background(), t.TempDir(), []string{"Cargo.toml"}, io.Discard)
	if len(got) != 1 {
		t.Fatalf("Install returned %d results, want 1", len(got))
	}
	if got[0].Status != InstallSkipped {
		t.Errorf("status = %q, want %q", got[0].Status, InstallSkipped)
	}
	if !strings.Contains(got[0].Reason, "no installer wired") {
		t.Errorf("reason = %q, want it to name the gap", got[0].Reason)
	}
	if InstallFailedAny(got) {
		t.Error("a skipped install counted as a failure")
	}
}

// TestRequireVirtualenvRefusesTheSystemPython is the guard that stops the one
// command here that can reach outside the scanned directory. `pip install`
// mutates whichever interpreter is on PATH, which on most Linux distributions is
// the one the operating system depends on.
func TestRequireVirtualenvRefusesTheSystemPython(t *testing.T) {
	t.Setenv("VIRTUAL_ENV", "")
	t.Setenv("CONDA_PREFIX", "")
	dir := t.TempDir()
	if why := requireVirtualenv(dir); why == "" {
		t.Fatal("requireVirtualenv allowed an install into the system Python")
	} else if !strings.Contains(why, "virtualenv") {
		t.Errorf("reason = %q, want it to say what to do", why)
	}

	// A project-local .venv is enough on its own.
	venvPy := filepath.Join(dir, ".venv", "bin", "python")
	if err := os.MkdirAll(filepath.Dir(venvPy), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(venvPy, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if why := requireVirtualenv(dir); why != "" {
		t.Errorf("requireVirtualenv refused a project .venv: %s", why)
	}
	if got := pythonFor(dir); got != venvPy {
		t.Errorf("pythonFor = %q, want the project venv %q", got, venvPy)
	}
}

// TestInstallStreamsAndSucceeds exercises the whole path — probe, guard, argv
// sequence, live streaming, consistency check — against the self-exec stub, so
// it needs neither a network nor a package manager.
func TestInstallStreamsAndSucceeds(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", "{}")
	t.Setenv(helperEnv, "1")

	saved := installers
	t.Cleanup(func() { installers = saved })
	installers = map[string][]installer{"package.json": {{
		tool: "stub", when: always,
		probe:  helperArgv(t, "TestHelperExitsOK"),
		writes: []string{"stub.lock"},
		argv: func(string, string) [][]string {
			return [][]string{helperArgv(t, "TestHelperExitsOK")}
		},
	}}}

	var out bytes.Buffer
	got := Install(context.Background(), root, []string{"package.json"}, &out)
	if got[0].Status != InstallOK {
		t.Fatalf("status = %q (%s), want %q", got[0].Status, got[0].Reason, InstallOK)
	}
	// The command it ran must be visible: an install is minutes of real work and
	// a silent terminal is indistinguishable from a hang.
	if !strings.Contains(out.String(), "$ ") {
		t.Errorf("nothing was streamed to the caller:\n%s", out.String())
	}
}

// TestInstallReportsDirtyWhenTheToolExitsCleanOnABrokenEnvironment.
//
// pip does exactly this: it prints "ERROR: ... dependency conflicts", names the
// packages that no longer agree, and exits 0. Trusting that exit code alone
// reports a broken environment as a clean install — the same shape as `go list
// -e` succeeding on the errors it was asked to find.
func TestInstallReportsDirtyWhenTheToolExitsCleanOnABrokenEnvironment(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", "{}")
	t.Setenv(helperEnv, "1")

	saved := installers
	t.Cleanup(func() { installers = saved })
	installers = map[string][]installer{"package.json": {{
		tool: "stub", when: always,
		probe: helperArgv(t, "TestHelperExitsOK"),
		argv: func(string, string) [][]string {
			return [][]string{helperArgv(t, "TestHelperExitsOK")}
		},
		// The install succeeds; the environment it leaves does not check out.
		consistency: func(string) []string { return helperArgv(t, "TestHelperFails") },
	}}}

	got := Install(context.Background(), root, []string{"package.json"}, io.Discard)
	if got[0].Status != InstallDirty {
		t.Fatalf("status = %q, want %q — a clean exit is not a working environment",
			got[0].Status, InstallDirty)
	}
	if !strings.Contains(got[0].Reason, "incompatible") {
		t.Errorf("reason = %q, want it to name the inconsistency", got[0].Reason)
	}
	// It must not read as a failed install: the packages really did change, so
	// telling the user to re-run the whole thing would be wrong.
	if InstallFailedAny(got) {
		t.Error("a dirty environment was reported as a failed install")
	}
}

// TestInstallFailureKeepsTheTail — the stream has already scrolled past by the
// time the summary prints, so the end of it has to be repeated.
func TestInstallFailureKeepsTheTail(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", "{}")
	t.Setenv(helperEnv, "1")

	saved := installers
	t.Cleanup(func() { installers = saved })
	installers = map[string][]installer{"package.json": {{
		tool: "stub", when: always,
		probe: helperArgv(t, "TestHelperExitsOK"),
		argv: func(string, string) [][]string {
			return [][]string{helperArgv(t, "TestHelperFails")}
		},
	}}}

	got := Install(context.Background(), root, []string{"package.json"}, io.Discard)
	if got[0].Status != InstallFailed {
		t.Fatalf("status = %q, want %q", got[0].Status, InstallFailed)
	}
	if len(got[0].Detail) == 0 {
		t.Error("a failed install kept none of the tool's output")
	}
}

// TestRingHoldsOnlyTheTail. An install can emit tens of thousands of lines and
// none of them justify holding the whole stream in memory (invariant P2: memory
// is a function of the knobs, never of input size).
func TestRingHoldsOnlyTheTail(t *testing.T) {
	r := newRing(3)
	if got := r.lines(); len(got) != 0 {
		t.Errorf("empty ring = %v, want nothing", got)
	}
	r.add("a")
	r.add("b")
	if got := strings.Join(r.lines(), ","); got != "a,b" {
		t.Errorf("partial ring = %q, want %q", got, "a,b")
	}
	for _, s := range []string{"c", "d", "e"} {
		r.add(s)
	}
	if got := strings.Join(r.lines(), ","); got != "c,d,e" {
		t.Errorf("wrapped ring = %q, want the last three (%q)", got, "c,d,e")
	}
}
