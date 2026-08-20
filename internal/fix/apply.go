package fix

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotFixable reports a Target that Plan already marked unapplyable. Apply
// checks it again rather than trusting the caller: the interactive table and a
// --fix-all run are two callers, and only one of them has a user to warn.
var ErrNotFixable = errors.New("no manifest pin to rewrite")

// Result describes what one applied fix did, for the line the UI prints back —
// and, because it carries the versions on both sides, what Revert needs to undo
// it without re-planning.
type Result struct {
	File    string // path relative to the scan root
	Line    int
	Package string
	From    string // the version that was pinned
	To      string // the version now pinned
	Before  string // the line as it was
	After   string // the line as it now is

	Stale []string // lockfiles under the scan root the bump has just outdated
}

// Apply rewrites the pin one Target points at, from Current to Fixed.
//
// The edit is proved before it is made: the file is re-read, the line is
// re-checked for both the package name and the exact version the scan
// resolved, and only the version token is replaced. Everything else on the
// line — the comparison operator, an extras marker, a trailing comment, the
// indentation — survives byte-for-byte, because a remediation that reformats a
// manifest is a diff nobody can review.
//
// root is the scan root; t.File is interpreted relative to it and may not
// escape it.
func Apply(root string, t Target) (Result, error) {
	if !t.Fixable {
		if t.Reason != "" {
			return Result{}, fmt.Errorf("%s: %w (%s)", t.Package, ErrNotFixable, t.Reason)
		}
		return Result{}, fmt.Errorf("%s: %w", t.Package, ErrNotFixable)
	}

	before, after, err := edit(root, t.File, t.Line, t.Package, t.Current, t.Fixed)
	if err != nil {
		return Result{}, err
	}
	return Result{
		File: t.File, Line: t.Line, Package: t.Package,
		From: t.Current, To: t.Fixed,
		Before: before, After: after,
		Stale: staleLocks(root, t.File),
	}, nil
}

// Revert undoes one applied fix, putting the pin back exactly where it was.
//
// It runs through the same proved edit as Apply with the versions swapped: if
// the line no longer reads what the fix wrote, something else has changed it
// since, and restoring the old version would discard that change. Reverting
// re-opens the advisories the fix closed, which is the caller's decision to make
// and to say out loud.
func Revert(root string, r Result) error {
	_, _, err := edit(root, r.File, r.Line, r.Package, r.To, r.From)
	return err
}

// edit is the single proved rewrite both Apply and Revert go through: re-read
// the file, re-check that the line still declares pkg at version from, replace
// only that version token with to, and write the file back atomically.
//
// Returning the before/after line lets the caller report the change without
// re-reading anything.
func edit(root, file string, line int, pkg, from, to string) (before, after string, err error) {
	abs, err := resolveInRoot(root, file)
	if err != nil {
		return "", "", err
	}

	data, err := os.ReadFile(abs) // #nosec G304 -- path is confined to the scan root by resolveInRoot
	if err != nil {
		return "", "", fmt.Errorf("read %s: %w", file, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", "", fmt.Errorf("stat %s: %w", file, err)
	}

	lines := strings.Split(string(data), "\n")
	if line < 1 || line > len(lines) {
		return "", "", fmt.Errorf("%s:%d: line is past the end of the file — re-run the scan", file, line)
	}

	// A CRLF file splits into lines with a trailing \r; hold it aside so the
	// rewrite cannot silently convert the file's line endings.
	raw := lines[line-1]
	body, cr := raw, ""
	if trimmed, ok := strings.CutSuffix(raw, "\r"); ok {
		body, cr = trimmed, "\r"
	}

	if !mentionsPackage(body, pkg) {
		return "", "", fmt.Errorf("%s:%d no longer declares %s — re-run the scan", file, line, pkg)
	}
	next, ok := replaceVersion(body, from, to)
	if !ok {
		return "", "", fmt.Errorf("%s:%d no longer pins %s %s — re-run the scan", file, line, pkg, from)
	}
	if next == body {
		return "", "", fmt.Errorf("%s:%d already reads %s", file, line, to)
	}

	lines[line-1] = next + cr
	if err := writeFileAtomic(abs, []byte(strings.Join(lines, "\n")), info.Mode().Perm()); err != nil {
		return "", "", err
	}
	return strings.TrimSpace(body), strings.TrimSpace(next), nil
}

// resolveInRoot joins rel onto root and refuses anything that climbs out of it.
// A manifest path comes from an occurrence AIROM recorded, not from a user, but
// the fix path is the one place in the tool that WRITES — so it verifies rather
// than assumes.
func resolveInRoot(root, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("empty manifest path")
	}
	base, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve scan root: %w", err)
	}
	abs := filepath.Join(base, filepath.FromSlash(rel))
	if abs != base && !strings.HasPrefix(abs, base+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing to edit %s: outside the scan root", rel)
	}
	return abs, nil
}

// mentionsPackage reports whether line declares pkg, comparing under the
// normalization every ecosystem in scope tolerates: case-insensitive, and
// `_`/`.` equivalent to `-` (PEP 503 for PyPI, harmless elsewhere).
func mentionsPackage(line, pkg string) bool {
	return strings.Contains(normalizeName(line), normalizeName(pkg))
}

func normalizeName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, ".", "-")
	return s
}

// replaceVersion swaps the version token old for next inside line, leaving the
// rest of the line untouched. It matches only a WHOLE version token: "4.3" must
// not turn "4.30.0" into "4.53.00.0", and a version appearing inside a URL or a
// hash must not be mistaken for the pin.
//
// Go manifests spell the same version "v1.2.3" while the component carries
// "1.2.3", so the v-prefixed spelling is tried too and the replacement keeps
// whichever prefix the file already uses.
func replaceVersion(line, old, next string) (string, bool) {
	for _, c := range []struct{ from, to string }{
		{old, next},
		{"v" + strings.TrimPrefix(old, "v"), "v" + strings.TrimPrefix(next, "v")},
		{strings.TrimPrefix(old, "v"), strings.TrimPrefix(next, "v")},
	} {
		if c.from == "" {
			continue
		}
		if i := indexToken(line, c.from); i >= 0 {
			return line[:i] + c.to + line[i+len(c.from):], true
		}
	}
	return line, false
}

// indexToken returns the offset of the first occurrence of tok in s that stands
// as a complete version token — neither neighbour continues it. Returns -1 when
// there is none.
func indexToken(s, tok string) int {
	for off := 0; ; {
		i := strings.Index(s[off:], tok)
		if i < 0 {
			return -1
		}
		i += off
		end := i + len(tok)
		if !continuesVersion(s, i-1) && !continuesVersion(s, end) {
			return i
		}
		off = i + 1
		if off >= len(s) {
			return -1
		}
	}
}

// continuesVersion reports whether the byte at index i (out of range = no) would
// make an adjacent match part of a longer version-ish token.
func continuesVersion(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return true
	case c == '.':
		return true
	default:
		return false
	}
}

// writeFileAtomic writes data to path through a temp file in the same directory
// and renames it into place, so an interrupted fix leaves the manifest either
// wholly old or wholly new — never half-rewritten.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".airom-fix-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	if err := os.Chmod(name, perm); err != nil {
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// lockFor names the resolver output that a given manifest feeds, so a bump can
// say which file now disagrees with it. A stale lockfile is REPORTED, never
// rewritten: its contents are a resolution — hashes, transitive pins, a
// dependency graph — and only the package manager can compute the new one.
var lockFor = map[string][]string{
	"requirements.txt": {"requirements.lock"},
	"pyproject.toml":   {"poetry.lock", "uv.lock", "pdm.lock"},
	"Pipfile":          {"Pipfile.lock"},
	"package.json":     {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"},
	"go.mod":           {"go.sum"},
	"Cargo.toml":       {"Cargo.lock"},
	"build.gradle":     {"gradle.lockfile"},
	"build.gradle.kts": {"gradle.lockfile"},
}

// staleLocks lists the lockfiles beside manifest that the bump has just put out
// of date, as paths relative to root.
func staleLocks(root, manifest string) []string {
	dir := filepath.Dir(filepath.FromSlash(manifest))
	var out []string
	for _, name := range lockFor[filepath.Base(manifest)] {
		rel := filepath.ToSlash(filepath.Join(dir, name))
		abs, err := resolveInRoot(root, rel)
		if err != nil {
			continue
		}
		if st, err := os.Stat(abs); err == nil && !st.IsDir() {
			out = append(out, rel)
		}
	}
	return out
}
