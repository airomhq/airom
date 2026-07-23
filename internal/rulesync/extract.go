package rulesync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Extraction caps. Rule packs are tiny YAML; these ceilings bound a hostile or
// malformed bundle without constraining any real one.
const (
	maxEntries      = 4096
	maxTotalSize    = 16 << 20 // 16 MiB of pack bytes actually written
	maxFileSize     = 1 << 20  // 1 MiB per pack
	maxDecompressed = 64 << 20 // ceiling on the whole decompressed stream (gzip-bomb guard)
)

// install extracts a gzipped tar of rule packs into <cache>/rules/<version>,
// atomically: it writes to a temp dir and renames over the target, so a crashed
// or malformed extraction never leaves a half-written "current" bundle. Only
// regular *.yaml files under sanitized paths are written; anything else in the
// archive is ignored.
func install(cacheDir, version string, tarball []byte) (string, error) {
	root := rulesDir(cacheDir)
	if err := os.MkdirAll(root, 0o750); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(root, ".tmp-*")
	if err != nil {
		return "", err
	}
	// Best-effort cleanup if we fail before the rename.
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tmp)
		}
	}()

	if err := untar(tarball, tmp); err != nil {
		return "", err
	}

	final := filepath.Join(root, version)
	if err := os.RemoveAll(final); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		return "", err
	}
	committed = true
	return final, nil
}

func untar(tarball []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return fmt.Errorf("gunzip bundle: %w", err)
	}
	defer func() { _ = gz.Close() }()

	// Bound the DECOMPRESSED stream, not just the download: a small gzip can
	// expand to gigabytes, and the tar reader would faithfully decompress even
	// the entries we skip. Hitting the ceiling surfaces as a tar read error.
	tr := tar.NewReader(io.LimitReader(gz, maxDecompressed))
	var entries int
	var total int64
	wrote := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read bundle: %w", err)
		}
		if entries++; entries > maxEntries {
			return fmt.Errorf("bundle has more than %d entries", maxEntries)
		}
		name := normalizeName(h.Name)
		if name == "" {
			continue // absolute, root, or "../" escape → clamped to empty; skip
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(name, ".yaml") {
			continue // only regular pack files matter; ignore dirs, symlinks, etc.
		}
		if h.Size > maxFileSize {
			return fmt.Errorf("bundle entry %q exceeds %d bytes", name, maxFileSize)
		}
		if total += h.Size; total > maxTotalSize {
			return fmt.Errorf("bundle exceeds %d bytes uncompressed", maxTotalSize)
		}
		out := filepath.Join(dest, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return err
		}
		// #nosec G304 -- `out` is normalizeName-sanitized and joined under a fresh
		// temp dir; O_EXCL refuses to follow any pre-existing path.
		f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		// LimitReader is belt-and-suspenders: the header size was already
		// checked, but a lying header must never let a copy run unbounded.
		if _, err := io.Copy(f, io.LimitReader(tr, maxFileSize)); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		wrote = true
	}
	if !wrote {
		return fmt.Errorf("bundle contained no rule packs (*.yaml)")
	}
	return nil
}

// normalizeName sanitizes a tar entry path to a root-relative, forward-slashed
// path, clamping any "../" escape at the root and returning "" for an absolute
// or empty name. Mirrors internal/source/imagesource.normalizeName; kept local
// so rulesync stays decoupled from the image source.
func normalizeName(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	clean := path.Clean("/" + name) // a leading "/" makes Clean collapse any leading ".."
	clean = strings.TrimPrefix(clean, "/")
	if clean == "." || clean == "" {
		return ""
	}
	return clean
}
