package fix

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// InstallStatus is the outcome of running one manifest's package manager.
type InstallStatus string

// The three outcomes. Skipped is distinct from Failed on purpose: "no installer
// ran" and "the installer refused" are different answers, and a scan that
// reports the first as the second would send someone hunting a build break that
// never happened.
const (
	InstallOK InstallStatus = "ok"
	// InstallDirty means the command succeeded and the resulting environment is
	// nonetheless internally inconsistent. pip is the reason this status exists:
	// it prints "ERROR: ... dependency conflicts", names packages that no longer
	// agree, and exits 0. Reading that exit code alone would report a broken
	// environment as a clean install — the same shape as `go list -e` returning
	// success for the errors it was asked to find.
	InstallDirty   InstallStatus = "dirty"
	InstallFailed  InstallStatus = "failed"
	InstallSkipped InstallStatus = "skipped"
)

// InstallResult records what one manifest's package manager did.
type InstallResult struct {
	Manifest string
	Tool     string
	Status   InstallStatus
	Reason   string   // why it was skipped, or how it failed
	Detail   []string // the tail of the tool's own output, when it failed
	Wrote    []string // what the tool is expected to have created or rewritten
}

// InstallTimeout caps one package-manager run. Far longer than VerifyTimeout
// because this one genuinely downloads and builds: a cold `npm install` or a
// wheel that has to compile is minutes of honest work, not a hang.
const InstallTimeout = 20 * time.Minute

// installer is one ecosystem's "make the manifest real" command sequence.
//
// Unlike the dry-run checkers in verify.go, everything here WRITES: lockfiles,
// vendor directories, an interpreter's site-packages. That is the point — a
// rewritten pin that nothing has installed is a promise, not a fix — but it is
// also why this is behind its own flag and why every entry has to state what it
// touches.
type installer struct {
	tool string
	// when decides whether this variant applies, given the manifest's directory.
	// The first matching variant for a manifest wins, so lockfile-specific tools
	// are listed before the default.
	when func(dir string) bool
	// probe reports the tool is usable at all, without touching the project.
	probe []string
	// argv is the command sequence, run in order; all must succeed. A sequence
	// rather than one command because some managers separate locking from
	// installing.
	argv func(dir, manifest string) [][]string
	// writes names what the run is expected to create or rewrite, for the report.
	writes []string
	// guard can veto with a human reason before anything runs.
	guard func(dir string) string
	// consistency is a command that reports whether the installed set agrees
	// with itself. Run once before and once after, so an inconsistency can be
	// attributed rather than merely announced — a package manager that exits 0
	// having just broken the environment is exactly the case this catches.
	consistency func(dir string) []string
}

// installers maps a manifest basename to its candidate installers, most
// specific first.
//
// Only ecosystems whose command sequence has been run for real are here.
// Cargo, Poetry, and Pipenv are deliberately absent: their invocations differ
// across major versions (`poetry lock --no-update` was removed in 2.x), and an
// untested command string is the same class of mistake as a flag that does the
// opposite of what it reads like. They report "no installer wired" — an honest
// gap, and an obvious place to add one.
var installers = map[string][]installer{
	"requirements.txt": {{
		tool:   "pip",
		when:   always,
		probe:  []string{"python3", "-m", "pip", "--version"},
		guard:  requireVirtualenv,
		writes: []string{"the active Python environment"},
		consistency: func(dir string) []string {
			return []string{pythonFor(dir), "-m", "pip", "check"}
		},
		argv: func(dir, manifest string) [][]string {
			return [][]string{{pythonFor(dir), "-m", "pip", "install", "--no-input", "-r", manifest}}
		},
	}},
	"package.json": {
		{
			tool: "pnpm", when: lockPresent("pnpm-lock.yaml"),
			probe: []string{"pnpm", "--version"}, writes: []string{"pnpm-lock.yaml", "node_modules/"},
			argv: func(string, string) [][]string { return [][]string{{"pnpm", "install"}} },
		},
		{
			tool: "yarn", when: lockPresent("yarn.lock"),
			probe: []string{"yarn", "--version"}, writes: []string{"yarn.lock", "node_modules/"},
			argv: func(string, string) [][]string { return [][]string{{"yarn", "install"}} },
		},
		{
			tool: "npm", when: always,
			probe: []string{"npm", "--version"}, writes: []string{"package-lock.json", "node_modules/"},
			argv: func(string, string) [][]string {
				return [][]string{{"npm", "install", "--no-audit", "--no-fund"}}
			},
		},
	},
	"pyproject.toml": {{
		tool: "uv", when: lockPresent("uv.lock"),
		probe: []string{"uv", "--version"}, writes: []string{"uv.lock", ".venv/"},
		argv: func(string, string) [][]string { return [][]string{{"uv", "sync"}} },
	}},
	"go.mod": {{
		tool: "go", when: always,
		probe: []string{"go", "version"}, writes: []string{"go.mod", "go.sum"},
		// tidy rather than `go get`: the manifest already carries the new
		// version, and tidy is what reconciles go.sum and the module graph with
		// it without deciding anything else.
		argv: func(string, string) [][]string { return [][]string{{"go", "mod", "tidy"}} },
	}},
}

func always(string) bool { return true }

// lockPresent matches a variant only when the resolver output it owns is
// already in the project — the reliable signal for which of several
// interchangeable managers this project actually uses.
func lockPresent(name string) func(string) bool {
	return func(dir string) bool {
		st, err := os.Stat(filepath.Join(dir, name))
		return err == nil && !st.IsDir()
	}
}

// pythonFor picks the interpreter to install into: a project-local .venv first,
// then an activated environment, then python3.
//
// A project .venv is preferred over an activated one because it is the
// environment this manifest describes; installing its dependencies somewhere
// else would leave both environments wrong.
func pythonFor(dir string) string {
	if p := filepath.Join(dir, ".venv", "bin", "python"); isExecutable(p) {
		return p
	}
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		if p := filepath.Join(venv, "bin", "python"); isExecutable(p) {
			return p
		}
	}
	return "python3"
}

func isExecutable(p string) bool {
	// #nosec G703 -- a metadata stat, never a read or a write. The path is the
	// scan-root-confined manifest directory plus fixed segments, or the user's
	// own VIRTUAL_ENV; no file content is opened and nothing is created. The
	// answer only decides which interpreter to name in an argv, and
	// requireVirtualenv is the guard that decides whether to run it at all.
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// requireVirtualenv refuses to install into an interpreter nobody scoped to this
// project.
//
// `pip install` is the one command here that reaches outside the directory being
// scanned: it mutates whichever interpreter is on PATH, which on most Linux
// distributions is the one the operating system depends on. PEP 668 marks those
// externally managed and pip declines — but relying on that is relying on a
// guard someone else installed, and a machine without it would have AIROM
// silently upgrading system packages. So this checks first, and says what to do.
func requireVirtualenv(dir string) string {
	if isExecutable(filepath.Join(dir, ".venv", "bin", "python")) {
		return ""
	}
	if os.Getenv("VIRTUAL_ENV") != "" || os.Getenv("CONDA_PREFIX") != "" {
		return ""
	}
	return "no virtualenv is active and no .venv/ is beside the manifest; " +
		"activate one (or create .venv) so the install cannot reach the system Python"
}

// Install runs each manifest's package manager so the rewritten pins become the
// versions actually resolved and installed.
//
// This is the half a manifest edit cannot do. Bumping `langchain==0.2.16` to
// `1.3.9` states an intention; until a resolver runs, the lockfile still pins
// the vulnerable release and the installed environment still contains it, so a
// build from that tree reinstalls exactly the advisory the fix was supposed to
// close.
//
// Output streams to out as it arrives, prefixed per tool. An install is minutes
// of real work, and a silent terminal for minutes is indistinguishable from a
// hang.
func Install(ctx context.Context, root string, manifests []string, out io.Writer) []InstallResult {
	var results []InstallResult
	for _, m := range dedupe(manifests) {
		results = append(results, installOne(ctx, root, m, out))
	}
	return results
}

func installOne(ctx context.Context, root, manifest string, out io.Writer) InstallResult {
	res := InstallResult{Manifest: manifest}

	dir, err := resolveInRoot(root, path.Dir(manifest))
	if err != nil {
		res.Status, res.Reason = InstallSkipped, err.Error()
		return res
	}

	inst, ok := pickInstaller(path.Base(manifest), dir)
	if !ok {
		res.Status = InstallSkipped
		res.Reason = "no installer wired for " + path.Base(manifest)
		return res
	}
	res.Tool, res.Wrote = inst.tool, inst.writes

	if inst.guard != nil {
		if why := inst.guard(dir); why != "" {
			res.Status, res.Reason = InstallSkipped, why
			return res
		}
	}
	if _, err := exec.LookPath(inst.probe[0]); err != nil {
		res.Status, res.Reason = InstallSkipped, inst.tool+" is not on PATH"
		return res
	}
	if _, halted, err := run(ctx, dir, inst.probe, probeTimeout); err != nil {
		if halted {
			res.Status, res.Reason = InstallSkipped, haltReason(inst.tool, err)
		} else {
			res.Status, res.Reason = InstallSkipped, inst.tool+" is not usable: "+err.Error()
		}
		return res
	}

	// The before-picture, so an inconsistency afterwards can be told apart from
	// one the environment already had.
	consistentBefore := true
	if inst.consistency != nil {
		_, _, cerr := run(ctx, dir, inst.consistency(dir), probeTimeout)
		consistentBefore = cerr == nil
	}

	for _, argv := range inst.argv(dir, path.Base(manifest)) {
		fmt.Fprintf(out, "  $ %s   (in %s)\n", strings.Join(argv, " "), manifest)
		tail, halted, err := runStreaming(ctx, dir, argv, InstallTimeout, out, "    ")
		if err != nil {
			res.Status = InstallFailed
			if halted {
				res.Status, res.Reason = InstallSkipped, haltReason(inst.tool, err)
			} else {
				res.Reason = strings.Join(argv, " ") + " failed"
			}
			res.Detail = tail
			return res
		}
	}
	res.Status = InstallOK

	// Exit zero is not the same as a working environment.
	if inst.consistency != nil {
		out, _, cerr := run(ctx, dir, inst.consistency(dir), probeTimeout)
		if cerr != nil {
			res.Status = InstallDirty
			res.Detail = lastLines(out, tailLines)
			if consistentBefore {
				res.Reason = inst.tool + " exited cleanly, but the environment it produced has incompatible packages"
			} else {
				res.Reason = inst.tool + " exited cleanly; the environment already had incompatible packages before this install"
			}
		}
	}
	return res
}

// lastLines returns the final n non-empty lines of a command's output.
func lastLines(out string, n int) []string {
	var kept []string
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		if l = strings.TrimRight(l, " \t"); l != "" {
			kept = append(kept, l)
		}
	}
	if len(kept) > n {
		kept = kept[len(kept)-n:]
	}
	return kept
}

// pickInstaller returns the first variant whose `when` matches this project.
func pickInstaller(base, dir string) (installer, bool) {
	for _, i := range installers[base] {
		if i.when == nil || i.when(dir) {
			return i, true
		}
	}
	return installer{}, false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// tailLines is how much of a failed install's output is kept for the summary.
// The full stream already went to the terminal; this is the part worth repeating
// once the scrollback has moved on.
const tailLines = 15

// runStreaming executes argv in dir, forwarding its output to out line by line
// as it arrives and keeping the last tailLines for the caller's report.
func runStreaming(ctx context.Context, dir string, argv []string, timeout time.Duration, out io.Writer, prefix string) (tail []string, halted bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv is a fixed table entry plus a manifest basename; no shell
	cmd.Dir = dir
	cmd.Stdin = nil
	cmd.Env = append(cmd.Environ(), "PIP_DISABLE_PIP_VERSION_CHECK=1", "NO_COLOR=1")

	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	cmd.Stderr = cmd.Stdout // one interleaved stream, in the order the tool wrote it

	if err := cmd.Start(); err != nil {
		return nil, false, err
	}

	ring := newRing(tailLines)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(pipe)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			ring.add(line)
			fmt.Fprintf(out, "%s%s\n", prefix, line)
		}
	}()

	waitErr := cmd.Wait()
	wg.Wait() // the reader must finish before the tail is read

	if cerr := ctx.Err(); cerr != nil {
		return ring.lines(), true, cerr
	}
	return ring.lines(), false, waitErr
}

// ring keeps the last n lines of a stream without growing with its length — an
// install can emit tens of thousands of lines, and none of them justify holding
// the whole thing in memory (invariant P2: memory is a function of the knobs,
// never of input size).
type ring struct {
	buf  []string
	next int
	full bool
}

func newRing(n int) *ring { return &ring{buf: make([]string, n)} }

func (r *ring) add(s string) {
	r.buf[r.next] = s
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

func (r *ring) lines() []string {
	if !r.full {
		return append([]string(nil), r.buf[:r.next]...)
	}
	out := make([]string, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	return append(out, r.buf[:r.next]...)
}

// InstallFailedAny reports whether any manifest's install did not succeed
// outright. A dirty environment is reported separately: the install ran, and
// the packages did change, so telling the user to re-run it would be wrong.
func InstallFailedAny(rs []InstallResult) bool {
	for _, r := range rs {
		if r.Status == InstallFailed {
			return true
		}
	}
	return false
}

// ErrNoInstaller reports that a manifest has no wired package manager.
var ErrNoInstaller = errors.New("no installer wired for this manifest")
