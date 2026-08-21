package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/airomhq/airom/internal/fix"
	"github.com/airomhq/airom/internal/fix/fixui"
	"github.com/airomhq/airom/pkg/airom"
)

// The remediation report goes to the shared stderr sink (progress.go), never
// stdout: stdout carries the AIBOM and invariant P7 requires it to be
// byte-identical for identical inputs. What a fix session did is a side effect
// of this run, not part of the bill.
//
// runFixes is the remediation stage: it turns the CVE overlay into a plan and
// either opens the interactive table (--fix) or applies every fixable pin
// (--fix-all).
//
// It runs AFTER emit, never before. The emitted AIBOM describes the tree as the
// scan found it; rewriting a manifest first would publish a document that
// matches no state the software was ever in. For the same reason the CI gate
// that follows still evaluates the scanned inventory: this run found those
// advisories, and the fix is a change to verify on the next scan, not a
// retroactive edit to this one.
func runFixes(ctx context.Context, inv *airom.Inventory, cfg *Config) error {
	if !cfg.Fix && !cfg.FixAll {
		return nil
	}
	// The SAME filter emit() applies, not an equivalent one. The fix table has
	// to describe the inventory the AIBOM describes, and keeping that in one
	// function is what stops the two drifting the next time it grows a step.
	if cfg.MinConfidence > 0 {
		inv = presentationFilter(inv, cfg)
	}
	targets := fix.Plan(inv, cfg.IncludeTests)
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "\nairom fix: no advisory names a version to upgrade to — nothing to fix.")
		return nil
	}

	// The baseline is taken BEFORE anything is edited, so a conflict afterwards
	// can be attributed. Without it a manifest that already did not resolve gets
	// blamed on the fix, and the revert offer would roll back real remediation
	// to "solve" a problem it did not cause.
	baseline := baselineVerify(ctx, cfg, targets)

	if cfg.FixAll {
		applied := applyAll(cfg.Target, targets)
		installFixes(ctx, cfg, applied, verifyFixes(ctx, cfg, applied, baseline))
		return nil
	}

	out, err := fixui.Run(cfg.Target, targets)
	if errors.Is(err, fixui.ErrNoTTY) {
		// No terminal to click in. Say what the table would have offered and
		// name the flag that does it without one, rather than failing a scan
		// that otherwise succeeded.
		s := fix.Summarize(targets)
		fmt.Fprintf(stderr, "\nairom fix: --fix needs a terminal; %d of %d vulnerable package(s) can be fixed:\n\n%s\nRe-run with --fix-all to apply them non-interactively.\n",
			s.Fixable, len(targets), fixui.Report(targets))
		return nil
	}
	if err != nil {
		return fmt.Errorf("interactive fix: %w", err)
	}
	reportApplied(out.Applied, out.Failed)
	installFixes(ctx, cfg, out.Applied, verifyFixes(ctx, cfg, out.Applied, baseline))
	return nil
}

// applyAll is the non-interactive path: fix everything fixable, then say
// exactly what changed and what still needs a human. Returns what it applied,
// for verification.
func applyAll(root string, targets []fix.Target) []fix.Result {
	var applied []fix.Result
	var failed int
	for _, t := range targets {
		if !t.Fixable {
			continue
		}
		res, err := fix.Apply(root, t)
		applied = append(applied, res...)
		if err != nil {
			// Partial is not success. A package still pinned vulnerable in one
			// manifest is still vulnerable, whatever the other manifests now say.
			if len(res) > 0 {
				fmt.Fprintf(stderr, "airom fix: %s: only %d of %d manifest(s) updated:\n",
					t.Package, len(res), len(t.Sites))
			} else {
				fmt.Fprintf(stderr, "airom fix: %s:\n", t.Package)
			}
			for _, line := range strings.Split(err.Error(), "\n") {
				fmt.Fprintf(stderr, "  %s\n", line)
			}
			failed++
		}
	}
	reportApplied(applied, failed)

	var manual []fix.Target
	for _, t := range targets {
		if !t.Fixable {
			manual = append(manual, t)
		}
	}
	if len(manual) > 0 {
		fmt.Fprintf(stderr, "\n%d package(s) need a manual change:\n%s", len(manual), fixui.Report(manual))
	}
	return applied
}

// reportApplied prints the post-session summary: the pins that moved, the
// lockfiles the bump has just outdated, and the reminder that only a fresh scan
// can confirm the advisories are gone.
//
// It reads the package name off each Result rather than off a parallel slice
// indexed in lockstep. The two can only diverge by a mistake, and the cost of
// that mistake — an index panic after the AIBOM is written and the tree is
// already edited — is out of all proportion to the convenience.
func reportApplied(applied []fix.Result, failed int) {
	if len(applied) == 0 {
		if failed > 0 {
			fmt.Fprintf(stderr, "\nairom fix: no pins changed; %d fix(es) failed.\n", failed)
		} else {
			fmt.Fprintln(stderr, "\nairom fix: no pins changed.")
		}
		return
	}

	fmt.Fprintf(stderr, "\nairom fix: updated %d pin(s)\n", len(applied))
	stale := map[string]bool{}
	for _, r := range applied {
		fmt.Fprintf(stderr, "  %s:%d  %s  →  %s   (%s)\n", r.File, r.Line, r.Before, r.After, r.Package)
		for _, l := range r.Stale {
			stale[l] = true
		}
	}
	if failed > 0 {
		fmt.Fprintf(stderr, "  %d fix(es) failed (see above)\n", failed)
	}

	if len(stale) > 0 {
		names := make([]string, 0, len(stale))
		for l := range stale {
			names = append(names, l)
		}
		sort.Strings(names)
		fmt.Fprintf(stderr, "\nThese lockfiles now disagree with the manifests and must be regenerated by their package manager:\n")
		for _, n := range names {
			fmt.Fprintf(stderr, "  %s\n", n)
		}
	}
	fmt.Fprintln(stderr, "\nRe-run the scan to confirm the advisories are cleared.")
}

// verifyFixes runs each touched manifest through its ecosystem's resolver in
// dry-run mode and reports the verdict.
//
// It exists because the two questions are not the same one. "Does this version
// clear the advisory?" is answered per package, from OSV. "Do the bumped
// versions resolve TOGETHER?" is a global question about a dependency graph
// AIROM does not model, and only the ecosystem's own resolver can answer it. A
// fix that closes eight CVEs and leaves a manifest nothing can install has
// traded a disclosed problem for an undisclosed one.
//
// A conflict is reported, never silently repaired: on a terminal the user is
// offered the revert, and everywhere else the pins stand and the clash is
// printed, because rolling back somebody's tree without asking is its own
// surprise.
func verifyFixes(ctx context.Context, cfg *Config, applied []fix.Result, baseline []fix.VerifyResult) (conflicted bool) {
	if !cfg.FixVerify || len(applied) == 0 {
		return false
	}
	manifests := make([]string, 0, len(applied))
	for _, r := range applied {
		manifests = append(manifests, r.File)
	}

	fmt.Fprintf(stderr, "\nairom fix: verifying the new pins resolve (dry run — nothing is installed)\n")
	results := fix.Verify(ctx, cfg.Target, manifests)
	attr := fix.Attribute(baseline, results)
	reportVerify(results, attr)

	// Only a conflict the fixes CAUSED is worth undoing. Reverting a
	// pre-existing one re-opens advisories without repairing anything.
	if !fix.Introduced(attr) {
		return false
	}
	offerRevert(cfg, applied)
	return true
}

// installFixes runs each edited manifest's package manager for real, so the
// rewritten pin becomes the version that is actually resolved and installed.
//
// A manifest edit on its own is a statement of intent. The lockfile beside it
// still pins the vulnerable release, and the environment still has it installed
// — so `npm ci`, or a fresh container build, or simply the next developer,
// reinstalls precisely the advisory the fix was supposed to close. This is the
// step that makes the edit true.
//
// It is skipped when verification found a conflict the fixes introduced: the
// resolver has already said this will not resolve, and starting a real install
// against it spends minutes to arrive at the same answer, having half-written a
// lockfile on the way.
func installFixes(ctx context.Context, cfg *Config, applied []fix.Result, conflicted bool) {
	if !cfg.FixInstall || len(applied) == 0 {
		return
	}
	if conflicted {
		fmt.Fprintln(stderr, "\nairom fix: skipping the install — the resolver already said these pins do not resolve.")
		return
	}

	manifests := make([]string, 0, len(applied))
	for _, r := range applied {
		manifests = append(manifests, r.File)
	}

	fmt.Fprintf(stderr, "\nairom fix: installing the new versions (this writes lockfiles and installs packages)\n")
	results := fix.Install(ctx, cfg.Target, manifests, stderr)
	reportInstall(results)
}

// reportInstall prints one line per manifest, naming what each tool wrote and
// repeating the tail of anything that failed.
func reportInstall(results []fix.InstallResult) {
	fmt.Fprintln(stderr)
	for _, r := range results {
		switch r.Status {
		case fix.InstallOK:
			wrote := ""
			if len(r.Wrote) > 0 {
				wrote = " — updated " + strings.Join(r.Wrote, ", ")
			}
			fmt.Fprintf(stderr, "  ✔ %s — %s installed the new versions%s\n", r.Manifest, r.Tool, wrote)
		case fix.InstallDirty:
			fmt.Fprintf(stderr, "  ! %s — %s\n", r.Manifest, r.Reason)
			for _, l := range r.Detail {
				fmt.Fprintf(stderr, "      %s\n", l)
			}
		case fix.InstallSkipped:
			fmt.Fprintf(stderr, "  · %s — not installed: %s\n", r.Manifest, r.Reason)
		case fix.InstallFailed:
			fmt.Fprintf(stderr, "  ✖ %s — %s\n", r.Manifest, r.Reason)
			for _, l := range r.Detail {
				fmt.Fprintf(stderr, "      %s\n", l)
			}
		}
	}
	if fix.InstallFailedAny(results) {
		// The manifests still carry the fixed pins; only the install did not
		// complete. Say which half is done, so nobody re-runs the whole thing
		// looking for the edit.
		fmt.Fprintln(stderr, "\nThe manifest pins are fixed; the install did not finish. Re-run the package manager yourself once the error above is resolved.")
	}
}

// baselineVerify records whether the manifests a plan would edit resolve BEFORE
// any of them is edited. Returns nil when there is nothing to check, which
// Attribute reads as "no verdict" rather than as "it was fine".
func baselineVerify(ctx context.Context, cfg *Config, targets []fix.Target) []fix.VerifyResult {
	if !cfg.FixVerify {
		return nil
	}
	manifests := fix.Manifests(targets)
	if len(manifests) == 0 {
		return nil
	}
	fmt.Fprintf(stderr, "\nairom fix: checking how these manifests resolve before any change (dry run)\n")
	results := fix.Verify(ctx, cfg.Target, manifests)
	for _, r := range results {
		if r.Status == fix.VerifyConflict {
			fmt.Fprintf(stderr, "  ! %s does not resolve as it stands, before any fix\n", r.Manifest)
		}
	}
	return results
}

// reportVerify prints one line per manifest, plus the resolver's own words for
// any that refused — and, for a refusal, whether the fix is what caused it.
func reportVerify(results []fix.VerifyResult, attr map[string]fix.Attribution) {
	for _, r := range results {
		switch r.Status {
		case fix.VerifyOK:
			fmt.Fprintf(stderr, "  ✔ %s — %s resolves the new pins\n", r.Manifest, r.Tool)
		case fix.VerifySkipped:
			fmt.Fprintf(stderr, "  · %s — not checked: %s\n", r.Manifest, r.Reason)
			for _, l := range r.Detail {
				fmt.Fprintf(stderr, "      %s\n", l)
			}
		case fix.VerifyErrored:
			fmt.Fprintf(stderr, "  · %s — check did not complete: %s\n", r.Manifest, r.Reason)
		case fix.VerifyConflict:
			switch attr[r.Manifest] {
			case fix.AttrPreexisting:
				fmt.Fprintf(stderr, "  ! %s — %s cannot resolve it, and could not before the fix either:\n", r.Manifest, r.Tool)
			case fix.AttrUnknown:
				fmt.Fprintf(stderr, "  ✖ %s — %s cannot resolve the new pins (no before-fix verdict, so this may predate them):\n", r.Manifest, r.Tool)
			default:
				fmt.Fprintf(stderr, "  ✖ %s — %s resolved this before the fix and cannot now:\n", r.Manifest, r.Tool)
			}
			for _, l := range r.Detail {
				fmt.Fprintf(stderr, "      %s\n", l)
			}
			if attr[r.Manifest] == fix.AttrPreexisting {
				fmt.Fprintf(stderr, "      the fix did not cause this; reverting it would re-open the advisories without repairing the clash\n")
			}
		}
	}
}

// offerRevert asks — on a terminal — whether to put the pins back, and does it.
// Without a terminal the edits stand and the report says how to undo them by
// hand, because an unattended run is exactly where a silent rollback would go
// unnoticed.
func offerRevert(cfg *Config, applied []fix.Result) {
	prompt := fmt.Sprintf("\nRevert all %d fix(es)? This re-opens the advisories they closed. [y/N] ", len(applied))
	yes, asked := fixui.Confirm(prompt)
	if !asked {
		// Nobody to ask. The edits stand — rolling back an unattended run
		// without a word is its own surprise — but the reverse edits are printed
		// so the tree can be put back by hand.
		fmt.Fprintf(stderr, "\nThe pins were kept. To undo them:\n")
		for _, r := range applied {
			fmt.Fprintf(stderr, "  %s:%d  %s  →  %s\n", r.File, r.Line, r.After, r.Before)
		}
		return
	}
	if !yes {
		fmt.Fprintln(stderr, "Keeping the fixes. Resolve the conflict, then re-run the scan.")
		return
	}

	var failed int
	for _, r := range applied {
		if err := fix.Revert(cfg.Target, r); err != nil {
			fmt.Fprintf(stderr, "airom fix: could not revert %s:%d: %v\n", r.File, r.Line, err)
			failed++
			continue
		}
		fmt.Fprintf(stderr, "  reverted %s:%d  %s\n", r.File, r.Line, r.Before)
	}
	if failed > 0 {
		fmt.Fprintf(stderr, "%d pin(s) could not be reverted; check them by hand.\n", failed)
	}
}
