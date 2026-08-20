package fix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
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
			return []string{"python3", "-m", "pip", "install", "--dry-run",
				"--report", os.DevNull, "--no-input", "-r", m}
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
		args: func(string) []string {
			// The module graph alone: it fails on a version that does not exist
			// and on a go.sum the bump has invalidated, without building or
			// writing anything.
			return []string{"go", "list", "-m", "-e", "all"}
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
	if _, _, err := run(ctx, dir, c.probe, 30*time.Second); err != nil {
		res.Status, res.Reason = VerifySkipped, c.tool+" is not usable: "+err.Error()
		return res
	}

	out, timedOut, err := run(ctx, dir, c.args(path.Base(manifest)), VerifyTimeout)
	switch {
	case timedOut:
		res.Status = VerifyErrored
		res.Reason = fmt.Sprintf("%s did not finish within %s", c.tool, VerifyTimeout)
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
func run(ctx context.Context, dir string, argv []string, timeout time.Duration) (out string, timedOut bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv is a fixed table entry plus a manifest basename; no shell
	cmd.Dir = dir
	// A resolver that stops to ask a question would hang the fix session.
	cmd.Stdin = nil
	cmd.Env = append(cmd.Environ(), "PIP_DISABLE_PIP_VERSION_CHECK=1", "NO_COLOR=1")

	b, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return string(b), true, ctx.Err()
	}
	return string(b), false, err
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
