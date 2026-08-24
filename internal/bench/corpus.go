package bench

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/airomhq/airom/internal/app"
	"github.com/airomhq/airom/pkg/airom"
)

// Entry is one corpus repo: a truth file plus either an extracted tree/ or a
// snapshot.tar.gz (stdlib-decodable on purpose; the corpus format follows the
// tool's zero-CGO, zero-extra-dependency discipline).
type Entry struct {
	Name  string
	Dir   string // corpus/<name>
	Truth *Truth
}

// LoadCorpus enumerates corpus entries under root/corpus (or root itself if
// it has no corpus/ subdirectory), validating every truth file up front: a
// broken label fails the run before any scanning, not mid-report.
func LoadCorpus(root string) ([]Entry, error) {
	base := filepath.Join(root, "corpus")
	if _, err := os.Stat(base); err != nil {
		base = root
	}
	des, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	var errs []string
	for _, de := range des {
		if !de.IsDir() {
			continue
		}
		dir := filepath.Join(base, de.Name())
		tp := filepath.Join(dir, "truth.yaml")
		if _, err := os.Stat(tp); err != nil {
			continue // not a corpus entry
		}
		truth, err := LoadTruth(tp)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		entries = append(entries, Entry{Name: de.Name(), Dir: dir, Truth: truth})
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, fmt.Errorf("invalid truth files:\n  %s", strings.Join(errs, "\n  "))
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no corpus entries under %s (need <name>/truth.yaml)", base)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// Run scans every entry and evaluates it, returning the results and the
// ToolInfo of the ruleset that produced them (every result is stamped with
// the rules that made it, same as every AIBOM). Scans are offline and
// fixed-config (no CVE, no EOL, no rule auto-update): the benchmark grades
// detection, and a metric that moves when OSV.dev does is not measuring the
// scanner.
func Run(ctx context.Context, entries []Entry) ([]*RepoResult, airom.ToolInfo, error) {
	var out []*RepoResult
	var tool airom.ToolInfo
	for _, e := range entries {
		tree, cleanup, err := materialize(e)
		if err != nil {
			return nil, tool, fmt.Errorf("%s: %w", e.Name, err)
		}
		// NoCachedRules: the benchmark grades the rules the binary SHIPS.
		// A cached bundle would make the numbers depend on machine state —
		// two machines, two results, one version string. The report records
		// rulesVersion/rulesHash either way, so what ran is never a guess.
		cfg := &app.Config{
			Source: app.SourceFS, Target: tree,
			CVE: false, NoEOL: true, AutoUpdateRules: false,
			NoCachedRules: true,
			Quiet:         true, NoProgress: true,
		}
		inv, err := app.Scan(ctx, cfg)
		cleanup()
		if err != nil {
			return nil, tool, fmt.Errorf("%s: scan: %w", e.Name, err)
		}
		tool = inv.Tool
		out = append(out, Evaluate(e.Name, inv, e.Truth))
	}
	return out, tool, nil
}

// materialize returns a scannable directory for the entry: tree/ as-is, or
// snapshot.tar.gz extracted to a temp dir.
func materialize(e Entry) (dir string, cleanup func(), err error) {
	nop := func() {}
	if st, err := os.Stat(filepath.Join(e.Dir, "tree")); err == nil && st.IsDir() {
		return filepath.Join(e.Dir, "tree"), nop, nil
	}
	snap := filepath.Join(e.Dir, "snapshot.tar.gz")
	if _, err := os.Stat(snap); err != nil {
		return "", nop, fmt.Errorf("no tree/ and no snapshot.tar.gz")
	}
	tmp, err := os.MkdirTemp("", "airom-bench-"+e.Name+"-")
	if err != nil {
		return "", nop, err
	}
	cleanup = func() { _ = os.RemoveAll(tmp) }
	if err := extractTarGz(snap, tmp); err != nil {
		cleanup()
		return "", nop, err
	}
	return tmp, cleanup, nil
}

// extractTarGz unpacks src into dst, refusing entries that would land outside
// it. Same traversal discipline as the OCI reader: an archive is attacker
// input until proven otherwise, corpus or not.
func extractTarGz(src, dst string) error {
	f, err := os.Open(src) // #nosec G304 -- corpus path given by the operator
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(filepath.FromSlash(hdr.Name))
		if clean == "." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || filepath.IsAbs(clean) {
			return fmt.Errorf("refusing archive entry %q: escapes the extraction root", hdr.Name)
		}
		target := filepath.Join(dst, clean)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return err
			}
			w, err := os.Create(target) // #nosec G304 -- confined above
			if err != nil {
				return err
			}
			// Bound the copy: a corpus snapshot has a soft cap of 50 MB per
			// docs/benchmark.md, so 256 MB per FILE is a corrupt archive,
			// not a big one.
			if _, err := io.Copy(w, io.LimitReader(tr, 256<<20)); err != nil {
				_ = w.Close()
				return err
			}
			if err := w.Close(); err != nil {
				return err
			}
		case tar.TypeXGlobalHeader:
			// Every tarball git produces opens with a pax_global_header
			// carrying the commit SHA. It is metadata, not a file, and
			// GitHub's codeload archives all have one — refusing it rejected
			// real corpus snapshots outright. Skip it; it extracts to nothing.
			continue
		default:
			// Symlinks and specials do not belong in a corpus snapshot;
			// skipping silently would hide a malformed archive.
			return fmt.Errorf("refusing archive entry %q: unsupported type %d", hdr.Name, hdr.Typeflag)
		}
	}
}
