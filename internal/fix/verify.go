package fix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// VerifyStatus is the outcome of one manifest's resolution check.
type VerifyStatus string

// The four outcomes. Skipped and Errored are distinct from Conflict on purpose:
// "the resolver disagreed with these pins" and "no resolver ran" are different
// answers, and collapsing them would let a missing toolchain read as a clean
// bill of health.
const (
	VerifyOK       VerifyStatus = "ok"       // the resolver accepted the pins
	VerifyConflict VerifyStatus = "conflict" // the resolver refused them
	VerifySkipped  VerifyStatus = "skipped"  // no checker for this manifest, or the tool is absent
	VerifyErrored  VerifyStatus = "errored"  // the checker itself failed (timeout, crash)
)

// VerifyResult is one manifest's check.
type VerifyResult struct {
	Manifest string // path relative to the scan root
	Tool     string // "pip", "npm", ...
	Status   VerifyStatus
	Reason   string   // why it was skipped or errored
	Detail   []string // the resolver's own explanation, trimmed to the useful part
}

// Conflicted reports whether any manifest's pins were refused.
func Conflicted(rs []VerifyResult) bool {
	for _, r := range rs {
		if r.Status == VerifyConflict {
			return true
		}
	}
	return false
}

// probeTimeout caps the availability probe. Generous, because it is meant to
// answer "is this tool here at all" rather than to bound real work.
const probeTimeout = 30 * time.Second

// haltReason describes a command the context ended, distinguishing the user
// giving up from the tool taking too long. Both mean the same thing for the
// verdict — nothing was learned — but not for what to do about it.
func haltReason(tool string, err error) string {
	if errors.Is(err, context.Canceled) {
		return tool + " was interrupted before it reached a verdict"
	}
	return fmt.Sprintf("%s did not finish within %s", tool, VerifyTimeout)
}

// VerifyTimeout caps one resolver run. A dependency resolver can spend a long
// time backtracking, and a fix session must not hang on it.
const VerifyTimeout = 3 * time.Minute

// checker is one ecosystem's dry-run resolution command.
//
// Dry-run only, always: verification answers "would these pins install?" and
// must never be the thing that installs them. A tool with no dry-run mode gets
// no checker rather than a destructive approximation.
type checker struct {
	tool string
	// probe reports whether the tool is usable at all, without touching the
	// project. Its failure is a skip, never a conflict.
	probe []string
	// args builds the check command for a manifest, relative to the scan root.
	args func(manifest string) []string
	// stage, when set, prepares an out-of-tree working directory for the
	// check and returns it with a cleanup. It exists for resolvers that cannot
	// judge a manifest without also rewriting its lockfile: the copy absorbs
	// the write, the project is never touched, and the verdict is real.
	stage func(dir string) (runDir string, cleanup func(), err error)
	// env is appended to the check command's environment.
	env []string
	// markers begin the part of the output worth showing. The first one that
	// appears wins; when none do, the tail of the output is used.
	markers []string
	// inconclusive marks output that means the resolver never reached a verdict
	// — it is too old to ask, or it refused for a reason about the machine
	// rather than about the pins. Matching here turns a nonzero exit into a
	// skip, because reporting "your pins conflict" when pip actually said
	// "this Python is externally managed" would be a fabricated finding.
	inconclusive []string
}

// checkers maps a manifest basename to its resolution check.
//
// Only ecosystems whose resolver has a real, non-mutating dry-run are here.
// pyproject.toml, Cargo.toml, pom.xml, and build.gradle are deliberately
// absent: their toolchains resolve by writing a lockfile, and a check that
// mutates the tree is not a check. Those manifests report VerifySkipped with
// that reason, which is the honest answer.
var checkers = map[string]checker{
	"requirements.txt": {
		tool:  "pip",
		probe: []string{"python3", "-m", "pip", "--version"},
		args: func(m string) []string {
			// --report is load-bearing, not decoration: it puts pip in
			// resolution-reporting mode, which skips the install-target checks.
			// Without it a PEP 668 "externally managed" Python — every Debian
			// and Ubuntu system Python — refuses before resolving anything, and
			// the refusal looks exactly like a dependency conflict.
			//
			// NOT --quiet, though. Under it pip prints the one-line "Cannot
			// install" verdict and swallows the "The conflict is caused by:"
			// block naming which requirement clashes with which — the only part
			// of the output worth showing a user.
			return []string{
				"python3", "-m", "pip", "install", "--dry-run",
				"--report", os.DevNull, "--no-input", "-r", m,
			}
		},
		markers: []string{"The conflict is caused by:", "ResolutionImpossible", "ERROR:"},
		inconclusive: []string{
			"no such option", "unrecognized arguments",
			"externally-managed-environment", "externally managed",
		},
	},
	"package.json": {
		tool:  "npm",
		probe: []string{"npm", "--version"},
		args: func(string) []string {
			return []string{"npm", "install", "--dry-run", "--no-audit", "--no-fund"}
		},
		markers: []string{"Could not resolve dependency", "ERESOLVE", "npm error", "npm ERR!"},
		inconclusive: []string{
			"Unknown argument", "unknown option",
			"EACCES", "ENOTFOUND", "ETIMEDOUT", "network", // the machine, not the pins
		},
	},
	"go.mod": {
		tool:  "go",
		probe: []string{"go", "version"},
		// Staged out of tree, on purpose. EVERY go.mod edit invalidates go.sum,
		// so judging the project in place made `go list -m all` fail on
		// "missing go.sum entry" after every single fix — read as a conflict
		// the fix introduced, which then offered to revert correct
		// remediations on every Go project. That is the expected mechanical
		// consequence of the edit, not a verdict about the pins. The copy
		// carries go.mod and go.sum; -mod=mod lets go regenerate go.sum THERE,
		// the project's files stay byte-identical, and the verdict that comes
		// back is about whether the new pins resolve.
		stage: stageGoModule,
		env:   []string{"GOFLAGS=-mod=mod", "GOWORK=off"},
		args: func(string) []string {
			// The module graph alone: it fails on a version that does not
			// exist, without building anything.
			//
			// Emphatically NOT -e. That flag exists to report module errors in
			// the output and exit 0 anyway, which is the opposite of what a
			// check needs: with it, `go list` returns success for the failure
			// this check is here to catch, and prints the bad version as though
			// it resolved. Verified: a parseable but nonexistent version exits 1
			// without -e and 0 with it.
			return []string{"go", "list", "-m", "all"}
		},
		markers:      []string{"missing go.sum entry", "go: ", "error"},
		inconclusive: []string{"unknown flag", "dial tcp", "connection refused"},
	},
}

// Verify runs each touched manifest's resolver in dry-run mode and reports what
// it said. It installs nothing and writes nothing to the project.
//
// This is the step that separates "the advisories are gone" from "the advisories
// are gone and this still builds". A per-package version bump is a local
// decision; whether the bumped set resolves TOGETHER is a global one, and only
// the ecosystem's own resolver can answer it.
//
// It needs the network and a toolchain, so every failure to run degrades to
// VerifySkipped with a reason — a fix session must not fail because pip is not
// installed.
func Verify(ctx context.Context, root string, manifests []string) []VerifyResult {
	seen := map[string]bool{}
	var uniq []string
	for _, m := range manifests {
		if !seen[m] {
			seen[m] = true
			uniq = append(uniq, m)
		}
	}
	sort.Strings(uniq)

	out := make([]VerifyResult, 0, len(uniq))
	for _, m := range uniq {
		out = append(out, verifyOne(ctx, root, m))
	}
	return out
}

func verifyOne(ctx context.Context, root, manifest string) VerifyResult {
	base := path.Base(manifest)
	c, ok := checkers[base]
	if !ok {
		return VerifyResult{
			Manifest: manifest, Status: VerifySkipped,
			Reason: "no non-mutating resolver check exists for " + base,
		}
	}
	res := VerifyResult{Manifest: manifest, Tool: c.tool}

	// The manifest's own directory is the resolver's working directory: npm and
	// go both resolve relative to where the manifest lives, not to the scan root.
	dir, err := resolveInRoot(root, path.Dir(manifest))
	if err != nil {
		res.Status, res.Reason = VerifySkipped, err.Error()
		return res
	}

	if _, err := exec.LookPath(c.probe[0]); err != nil {
		res.Status, res.Reason = VerifySkipped, c.tool+" is not on PATH"
		return res
	}
	// A halted probe is not a verdict about the tool. If the context ended while
	// the probe was still running — a Ctrl-C, or a deadline — then nothing was
	// learned about anything, and calling that "the tool is not usable" is the
	// same fabrication as calling a killed resolver a dependency conflict, one
	// level up.
	if _, halted, err := run(ctx, dir, c.probe, probeTimeout); err != nil {
		if halted {
			res.Status, res.Reason = VerifyErrored, haltReason(c.tool, err)
		} else {
			res.Status, res.Reason = VerifySkipped, c.tool+" is not usable: "+err.Error()
		}
		return res
	}

	runDir := dir
	if c.stage != nil {
		staged, cleanup, serr := c.stage(dir)
		if serr != nil {
			res.Status, res.Reason = VerifySkipped, c.tool+" could not be staged: "+serr.Error()
			return res
		}
		defer cleanup()
		runDir = staged
	}
	out, halted, err := run(ctx, runDir, c.args(path.Base(manifest)), VerifyTimeout, c.env...)
	switch {
	case halted:
		res.Status, res.Reason = VerifyErrored, haltReason(c.tool, err)
	case err == nil:
		res.Status = VerifyOK
	case containsAny(out, c.inconclusive):
		// The resolver failed for a reason about this machine, not about these
		// pins. Say that, rather than inventing a conflict it never reported.
		res.Status = VerifySkipped
		res.Reason = c.tool + " could not reach a verdict here"
		res.Detail = excerpt(out, c.markers)
	default:
		res.Status = VerifyConflict
		res.Detail = excerpt(out, c.markers)
	}
	return res
}

// run executes argv in dir and returns its combined output. The argv comes from
// the fixed table above plus a manifest basename; no shell is involved, so
// nothing in the project can influence what is executed.
// run reports halted when the context ended the command — a timeout or a
// Ctrl-C — so the caller can tell "no verdict" from "the resolver said no".
func run(ctx context.Context, dir string, argv []string, timeout time.Duration, env ...string) (out string, halted bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv is a fixed table entry plus a manifest basename; no shell
	cmd.Dir = dir
	// A resolver that stops to ask a question would hang the fix session.
	cmd.Stdin = nil
	cmd.Env = append(cmd.Environ(), "PIP_DISABLE_PIP_VERSION_CHECK=1", "NO_COLOR=1")
	cmd.Env = append(cmd.Env, env...)

	b, err := cmd.CombinedOutput()
	// A killed resolver never rendered a verdict. Reporting its nonzero exit as
	// a dependency conflict would invent a finding — and then drive the revert
	// prompt to propose undoing fixes that were fine.
	if cerr := ctx.Err(); cerr != nil {
		return string(b), true, cerr
	}
	return string(b), false, err
}

// stageGoModule copies go.mod and go.sum (when present) from dir into a fresh
// temp directory. `go list -m all` needs only the module graph, so this is
// enough to judge the pins, and anything go writes (a regenerated go.sum)
// lands in the copy. Cleanup removes the copy.
func stageGoModule(dir string) (string, func(), error) {
	tmp, err := os.MkdirTemp("", "airom-verify-go-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	// os.Root confines every read below dir structurally: a name that tried to
	// escape cannot resolve, which is a stronger guarantee than a comment
	// asserting these two constants are safe.
	src, err := os.OpenRoot(dir)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("open %s: %w", dir, err)
	}
	defer func() { _ = src.Close() }()

	for _, name := range []string{"go.mod", "go.sum"} {
		b, err := readRootFile(src, name)
		if err != nil {
			if name == "go.sum" && errors.Is(err, os.ErrNotExist) {
				continue // a module with no go.sum yet is legitimate
			}
			cleanup()
			return "", nil, fmt.Errorf("stage %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(tmp, name), b, 0o600); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return tmp, cleanup, nil
}

// readRootFile reads name from within root, which cannot escape it.
func readRootFile(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// maxDetailLines caps how much of a resolver's output is repeated back. Enough
// to name the clash, not so much that the answer scrolls off.
const maxDetailLines = 12

// excerpt pulls the explanatory part out of a resolver's output: everything
// from the first marker it recognizes, or the tail when it recognizes none.
// Blank lines and the resolver's own "for help visit ..." footer are dropped —
// they are noise in a report that has to fit on one screen.
func excerpt(out string, markers []string) []string {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")

	start := -1
	for i, l := range lines {
		if containsAny(l, markers) {
			start = i
			break
		}
	}
	if start < 0 {
		start = max(0, len(lines)-maxDetailLines)
	}

	var kept []string
	for _, l := range lines[start:] {
		l = strings.TrimRight(l, " \t")
		if l == "" || strings.Contains(l, "for help visit") {
			continue
		}
		kept = append(kept, l)
		if len(kept) == maxDetailLines {
			break
		}
	}
	return kept
}

// Attribution says whether a fix CAUSED a manifest to stop resolving, or merely
// inherited a manifest that already did not.
type Attribution string

// The three answers. Unknown is not a synonym for either: no baseline verdict
// means no attribution, and saying so beats picking the convenient one.
const (
	AttrIntroduced  Attribution = "introduced"  // resolved before the fix, conflicts after
	AttrPreexisting Attribution = "preexisting" // did not resolve before the fix either
	AttrUnknown     Attribution = "unknown"     // the before-check reached no verdict
)

// Attribute pairs a before-fix and after-fix verification by manifest and says,
// for each conflicting manifest, whether the fix is responsible.
//
// Without this a conflict is unattributable, and an unattributable conflict is
// dangerous in one specific way: it drives the offer to revert. A manifest that
// already did not resolve — a go.sum that was stale before anyone touched it, a
// peer-dependency clash the project has been carrying for months — would have
// its fixes rolled back, re-opening real advisories to "solve" a problem the fix
// did not create and the revert does not fix.
//
// Manifests with no conflict after the fix are absent from the result: there is
// nothing to attribute.
func Attribute(before, after []VerifyResult) map[string]Attribution {
	prior := make(map[string]VerifyStatus, len(before))
	for _, b := range before {
		prior[b.Manifest] = b.Status
	}
	out := map[string]Attribution{}
	for _, a := range after {
		if a.Status != VerifyConflict {
			continue
		}
		switch prior[a.Manifest] {
		case VerifyOK:
			out[a.Manifest] = AttrIntroduced
		case VerifyConflict:
			out[a.Manifest] = AttrPreexisting
		default: // skipped, errored, or never checked
			out[a.Manifest] = AttrUnknown
		}
	}
	return out
}

// Introduced reports whether any conflict is one the fixes caused — the only
// case where undoing them is the remedy.
func Introduced(attr map[string]Attribution) bool {
	for _, a := range attr {
		if a == AttrIntroduced {
			return true
		}
	}
	return false
}

// Manifests lists the distinct manifests a set of targets would edit, for the
// before-fix baseline. Only fixable targets: nothing else will be touched, and
// checking a manifest no fix will reach spends a resolver run on nothing.
func Manifests(ts []Target) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range ts {
		if !t.Fixable || t.File == "" || seen[t.File] {
			continue
		}
		seen[t.File] = true
		out = append(out, t.File)
	}
	sort.Strings(out)
	return out
}
