package imagesource

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Roro1727/airom/internal/classify"
)

const (
	whiteoutPrefix = ".wh."         // ".wh.<name>" removes <name> from lower layers
	whiteoutOpaque = ".wh..wh..opq" // hides all lower-layer content in the directory
)

var errZstdUnsupported = errors.New("zstd-compressed layers are unsupported in this build")

// layerSrc opens one layer's raw (possibly compressed) tar bytes, base→top in
// slice order.
type layerSrc struct {
	name string
	open func() (io.ReadCloser, error)
}

// materialize runs the one-time squash: parse the image, apply layers top→base
// with whiteout resolution, and spool each effective file. A parse failure is
// a fatal acquisition error; per-layer/per-file problems degrade to Unknowns.
func (s *Source) materialize() error {
	tmp, err := os.MkdirTemp(s.opts.TmpDir, "airom-image-")
	if err != nil {
		return fmt.Errorf("image source: create temp dir: %w", err)
	}
	s.mu.Lock()
	s.tmpDir = tmp
	s.mu.Unlock()

	layers, id, err := s.parseImage()
	if err != nil {
		return fmt.Errorf("image source %q: %w", s.target, err)
	}
	if id != "" {
		s.id = id
	}
	s.squash(layers)
	return nil
}

// squash applies layers from top to base, keeping the first (topmost) version
// of each path and honoring whiteouts/opaque markers from higher layers.
func (s *Source) squash(layers []layerSrc) {
	seen := map[string]bool{}
	removed := map[string]bool{}
	opaque := map[string]bool{}

	for i := len(layers) - 1; i >= 0; i-- {
		l := layers[i]
		localRemoved, localOpaque := s.squashLayer(l, seen, removed, opaque)
		// Fold this layer's whiteouts/opaques so LOWER layers respect them.
		for k := range localRemoved {
			removed[k] = true
		}
		for k := range localOpaque {
			opaque[k] = true
		}
	}

	sort.Slice(s.ordered, func(a, b int) bool { return s.ordered[a].ref.Path < s.ordered[b].ref.Path })
}

// squashLayer processes one layer against the already-finalized higher layers.
// It returns this layer's own whiteout/opaque sets (applied only to lower
// layers by the caller).
func (s *Source) squashLayer(l layerSrc, seen, removed, opaque map[string]bool) (localRemoved, localOpaque map[string]bool) {
	localRemoved = map[string]bool{}
	localOpaque = map[string]bool{}

	rc, err := l.open()
	if err != nil {
		s.record(l.name, "layer", err.Error())
		return
	}
	dec, closeFn, err := decompress(rc)
	if err != nil {
		_ = rc.Close()
		s.record(l.name, "layer", err.Error())
		return
	}
	defer func() { _ = closeFn() }()

	tr := tar.NewReader(dec)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.record(l.name, "layer", err.Error())
			return
		}
		name := normalizeName(hdr.Name)
		if name == "" {
			continue
		}
		base := path.Base(name)
		dir := path.Dir(name)
		if dir == "." {
			dir = ""
		}

		// Opaque check must precede the ".wh." prefix check (the opaque marker
		// also begins with ".wh.").
		if base == whiteoutOpaque {
			localOpaque[dir] = true
			continue
		}
		if trimmed, ok := strings.CutPrefix(base, whiteoutPrefix); ok {
			target := trimmed
			if dir != "" {
				target = dir + "/" + trimmed
			}
			localRemoved[normalizeName(target)] = true
			continue
		}

		if !isRegularType(hdr.Typeflag) {
			continue // dirs, symlinks, hardlinks, devices: not scannable content
		}
		if seen[name] || removed[name] || underOpaque(opaque, name) {
			continue // shadowed by a higher layer
		}

		sp, ref, err := s.spool(tr, name, hdr)
		if err != nil {
			s.record(name, "spool", err.Error())
			continue
		}
		seen[name] = true
		fe := &fileEntry{ref: ref, sp: sp}
		s.ordered = append(s.ordered, fe)
		s.byPath[name] = fe
	}
	return localRemoved, localOpaque
}

// underOpaque reports whether any ancestor directory of name is opaque.
func underOpaque(opaque map[string]bool, name string) bool {
	if len(opaque) == 0 {
		return false
	}
	if opaque[""] { // opaque at the image root hides everything below
		return true
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '/' {
			if opaque[name[:i]] {
				return true
			}
		}
	}
	return false
}

// isRegularType reports whether a tar type flag denotes a regular file. The
// legacy '\x00' flag (older writers) counts as regular, without referencing the
// deprecated tar.TypeRegA constant.
func isRegularType(flag byte) bool {
	return flag == tar.TypeReg || flag == '\x00'
}

// normalizeName cleans a tar entry name to a root-relative slash path, clamping
// any ".." escape at the root. Returns "" for the root or empty names.
func normalizeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	clean := path.Clean("/" + name)
	clean = strings.TrimPrefix(clean, "/")
	if clean == "." || clean == "" {
		return ""
	}
	return clean
}

// ── Spooling ────────────────────────────────────────────────────────────────

// spool captures a file's bytes per the memory/disk/header policy documented
// on the package. Allocations are bounded by the caps, never by the (untrusted)
// tar header size.
func (s *Source) spool(r io.Reader, name string, hdr *tar.Header) (*spooled, classify.FileRef, error) {
	ref := classify.FileRef{
		Path: name,
		Size: hdr.Size,
		// Mask to the 12 permission/setid/sticky bits before the narrowing
		// conversion; the value cannot overflow fs.FileMode's low bits.
		Mode:     fs.FileMode(hdr.Mode&0o7777) & fs.ModePerm, // #nosec G115 -- masked to 12 bits
		ModTime:  hdr.ModTime,
		Language: classify.LanguageOf(name),
	}

	head, err := readUpTo(r, s.opts.MaxMemPerFile+1)
	if err != nil {
		return nil, ref, err
	}
	if int64(len(head)) <= s.opts.MaxMemPerFile {
		// Whole file is in head.
		if s.reserveMem(int64(len(head))) {
			return &spooled{mem: head}, ref, nil
		}
		return s.spillWhole(head, name, ref)
	}
	// File is larger than MaxMemPerFile; head holds MaxMemPerFile+1 bytes.
	return s.spillStreaming(head, r, name, ref)
}

// spillWhole spills a fully-read (<= MaxMemPerFile) buffer to disk, or falls
// back to header-only when the disk budget is exhausted.
func (s *Source) spillWhole(data []byte, name string, ref classify.FileRef) (*spooled, classify.FileRef, error) {
	n := int64(len(data))
	if !s.reserveDisk(n) {
		return s.headerOnly(data, name, "spool over memory and disk budget"), ref, nil
	}
	p, err := s.writeTemp(data)
	if err != nil {
		s.releaseDisk(n)
		return s.headerOnly(data, name, "spill write failed: "+err.Error()), ref, nil
	}
	return &spooled{tmpPath: p}, ref, nil
}

// spillStreaming writes head plus the remaining stream to a temp file, bounded
// by MaxDiskPerFile and the disk budget; oversized files become header-only.
func (s *Source) spillStreaming(head []byte, r io.Reader, name string, ref classify.FileRef) (*spooled, classify.FileRef, error) {
	if ref.Size > s.opts.MaxDiskPerFile {
		return s.headerOnly(head, name, "exceeds MaxDiskPerFile"), ref, nil
	}
	reserve := ref.Size
	if reserve < int64(len(head)) {
		reserve = int64(len(head)) // header lied small; reserve at least what we hold
	}
	if !s.reserveDisk(reserve) {
		return s.headerOnly(head, name, "exceeds disk budget"), ref, nil
	}

	f, err := os.CreateTemp(s.tmpDir, "spill-")
	if err != nil {
		s.releaseDisk(reserve)
		return s.headerOnly(head, name, "spill create failed: "+err.Error()), ref, nil
	}
	if _, err := f.Write(head); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		s.releaseDisk(reserve)
		return nil, ref, err
	}
	// Bound the copy defensively in case the header understated the size.
	limit := s.opts.MaxDiskPerFile - int64(len(head)) + 1
	copied, err := io.Copy(f, io.LimitReader(r, limit))
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		s.releaseDisk(reserve)
		return nil, ref, err
	}
	total := int64(len(head)) + copied
	if total > s.opts.MaxDiskPerFile {
		_ = f.Close()
		_ = os.Remove(f.Name())
		s.releaseDisk(reserve)
		return s.headerOnly(head, name, "actual size exceeds MaxDiskPerFile"), ref, nil
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		s.releaseDisk(reserve)
		return nil, ref, err
	}
	s.adjustDisk(reserve, total)
	ref.Size = total
	return &spooled{tmpPath: f.Name()}, ref, nil
}

// headerOnly retains just the header prefix and records the truncation.
func (s *Source) headerOnly(data []byte, name, reason string) *spooled {
	n := int64(len(data))
	if n > s.opts.HeaderCap {
		n = s.opts.HeaderCap
	}
	prefix := make([]byte, n)
	copy(prefix, data[:n])
	s.record(name, "spool", "content truncated to header ("+reason+")")
	return &spooled{header: prefix}
}

func (s *Source) writeTemp(data []byte) (string, error) {
	f, err := os.CreateTemp(s.tmpDir, "spill-")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// ── Budget accounting (guarded by s.mu) ─────────────────────────────────────

func (s *Source) reserveMem(n int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.memUsed+n > s.opts.MemBudget {
		return false
	}
	s.memUsed += n
	return true
}

func (s *Source) reserveDisk(n int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.diskUsed+n > s.opts.DiskBudget {
		return false
	}
	s.diskUsed += n
	return true
}

func (s *Source) releaseDisk(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.diskUsed -= n
	if s.diskUsed < 0 {
		s.diskUsed = 0
	}
}

func (s *Source) adjustDisk(reserved, actual int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.diskUsed += actual - reserved
	if s.diskUsed < 0 {
		s.diskUsed = 0
	}
}

// readUpTo reads up to limit bytes from r with a bounded initial allocation.
func readUpTo(r io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(int(initialCap(limit)))
	_, err := io.CopyN(&buf, r, limit)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf.Bytes(), nil
}

func initialCap(limit int64) int64 {
	const maxCap = 1 << 20 // never preallocate more than 1 MiB
	if limit < maxCap {
		return limit
	}
	return maxCap
}

// decompress selects a decoder by magic bytes. It returns the decoded reader
// and a close function that closes the decoder and the underlying stream.
func decompress(rc io.ReadCloser) (io.Reader, func() error, error) {
	br := bufio.NewReader(rc)
	magic, _ := br.Peek(4)
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, rc.Close, err
		}
		return gz, func() error {
			_ = gz.Close()
			return rc.Close()
		}, nil
	case len(magic) >= 4 && magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd:
		return nil, rc.Close, errZstdUnsupported
	default:
		return br, rc.Close, nil
	}
}

// ── Image format parsing ────────────────────────────────────────────────────

// parseImage resolves the ordered (base→top) layers and image identity from an
// OCI layout directory, an OCI image-layout archive, or a docker-save archive.
func (s *Source) parseImage() ([]layerSrc, string, error) {
	st, err := os.Stat(s.target)
	if err != nil {
		return nil, "", err
	}
	if st.IsDir() {
		return s.parseOCILayoutDir(s.target)
	}
	names, err := s.explodeTar(s.target)
	if err != nil {
		return nil, "", err
	}
	if p, ok := names["manifest.json"]; ok {
		return s.parseDockerSave(names, p)
	}
	if p, ok := names["index.json"]; ok {
		return s.parseOCIArchive(names, p)
	}
	return nil, "", errors.New("not a docker-save or OCI archive (no manifest.json or index.json)")
}

// explodeTar materializes each regular entry of the outer archive to a temp
// file, returning cleaned-name → temp-path. Total materialized bytes are
// bounded by DiskBudget to defend against archive bombs.
func (s *Source) explodeTar(archivePath string) (map[string]string, error) {
	f, err := os.Open(archivePath) // #nosec G304 -- the user-supplied image archive path is the input
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	outer := filepath.Join(s.tmpDir, "outer")
	if err := os.MkdirAll(outer, 0o700); err != nil {
		return nil, err
	}

	names := map[string]string{}
	var total int64
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		if !isRegularType(hdr.Typeflag) {
			continue
		}
		name := normalizeName(hdr.Name)
		if name == "" {
			continue
		}
		out, err := os.CreateTemp(outer, "blob-")
		if err != nil {
			return nil, err
		}
		// Bound the copy: never let one archive exceed DiskBudget in total.
		remaining := s.opts.DiskBudget - total + 1
		if remaining <= 0 {
			_ = out.Close()
			_ = os.Remove(out.Name())
			return nil, fmt.Errorf("archive exceeds disk budget (%d bytes); raise Options.DiskBudget", s.opts.DiskBudget)
		}
		n, err := io.Copy(out, io.LimitReader(tr, remaining))
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(out.Name())
			return nil, err
		}
		total += n
		if total > s.opts.DiskBudget {
			_ = os.Remove(out.Name())
			return nil, fmt.Errorf("archive exceeds disk budget (%d bytes); raise Options.DiskBudget", s.opts.DiskBudget)
		}
		names[name] = out.Name()
	}
	return names, nil
}

// dockerManifest is the docker-save manifest.json shape (only the fields used).
type dockerManifest struct {
	Config string   `json:"Config"`
	Layers []string `json:"Layers"`
}

func (s *Source) parseDockerSave(names map[string]string, manifestPath string) ([]layerSrc, string, error) {
	data, err := os.ReadFile(manifestPath) // #nosec G304 -- our own exploded temp file
	if err != nil {
		return nil, "", err
	}
	var manifests []dockerManifest
	if err := json.Unmarshal(data, &manifests); err != nil {
		return nil, "", fmt.Errorf("parse manifest.json: %w", err)
	}
	if len(manifests) == 0 {
		return nil, "", errors.New("manifest.json has no entries")
	}
	m := manifests[0]

	id := ""
	if cp, ok := names[normalizeName(m.Config)]; ok {
		if cb, err := os.ReadFile(cp); err == nil { // #nosec G304 -- our own exploded temp file
			sum := sha256.Sum256(cb)
			id = "sha256:" + hex.EncodeToString(sum[:])
		}
	}

	layers := make([]layerSrc, 0, len(m.Layers))
	for _, ln := range m.Layers {
		tp, ok := names[normalizeName(ln)]
		if !ok {
			return nil, "", fmt.Errorf("layer %q missing from archive", ln)
		}
		layers = append(layers, tempLayer(ln, tp))
	}
	return layers, id, nil
}

// ociIndex / ociManifest cover the OCI fields used for layer resolution.
type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
}
type ociIndex struct {
	Manifests []ociDescriptor `json:"manifests"`
}
type ociManifest struct {
	Config ociDescriptor   `json:"config"`
	Layers []ociDescriptor `json:"layers"`
}

func (s *Source) parseOCIArchive(names map[string]string, indexPath string) ([]layerSrc, string, error) {
	idxData, err := os.ReadFile(indexPath) // #nosec G304 -- our own exploded temp file
	if err != nil {
		return nil, "", err
	}
	var idx ociIndex
	if err := json.Unmarshal(idxData, &idx); err != nil {
		return nil, "", fmt.Errorf("parse index.json: %w", err)
	}
	manDesc, err := firstImageManifest(idx)
	if err != nil {
		return nil, "", err
	}
	manPath, ok := names[blobKey(manDesc.Digest)]
	if !ok {
		return nil, "", fmt.Errorf("manifest blob %q missing from archive", manDesc.Digest)
	}
	manData, err := os.ReadFile(manPath) // #nosec G304 -- our own exploded temp file
	if err != nil {
		return nil, "", err
	}
	var man ociManifest
	if err := json.Unmarshal(manData, &man); err != nil {
		return nil, "", fmt.Errorf("parse manifest: %w", err)
	}
	layers := make([]layerSrc, 0, len(man.Layers))
	for _, ld := range man.Layers {
		tp, ok := names[blobKey(ld.Digest)]
		if !ok {
			return nil, "", fmt.Errorf("layer blob %q missing from archive", ld.Digest)
		}
		layers = append(layers, tempLayer(ld.Digest, tp))
	}
	return layers, manDesc.Digest, nil
}

func (s *Source) parseOCILayoutDir(dir string) ([]layerSrc, string, error) {
	idxData, err := os.ReadFile(filepath.Join(dir, "index.json")) // #nosec G304 -- user-supplied OCI layout dir
	if err != nil {
		return nil, "", fmt.Errorf("read index.json: %w", err)
	}
	var idx ociIndex
	if err := json.Unmarshal(idxData, &idx); err != nil {
		return nil, "", fmt.Errorf("parse index.json: %w", err)
	}
	manDesc, err := firstImageManifest(idx)
	if err != nil {
		return nil, "", err
	}
	blobsRoot := filepath.Join(dir, "blobs")
	blobPath := func(digest string) (string, error) {
		alg, hexv, ok := splitDigest(digest)
		if !ok {
			return "", fmt.Errorf("bad digest %q", digest)
		}
		p := filepath.Join(blobsRoot, alg, hexv)
		// Defense-in-depth: splitDigest already rejects path separators in the
		// digest components, but assert the joined path stays under blobs/
		// before any filesystem read — the digest is attacker-controlled JSON
		// from the layout's own index.json (security boundary).
		if p != blobsRoot && !strings.HasPrefix(p, blobsRoot+string(filepath.Separator)) {
			return "", fmt.Errorf("blob digest %q escapes the layout", digest)
		}
		return p, nil
	}
	manPath, err := blobPath(manDesc.Digest)
	if err != nil {
		return nil, "", err
	}
	manData, err := os.ReadFile(manPath) // #nosec G304 -- path derived from the layout's own index
	if err != nil {
		return nil, "", err
	}
	var man ociManifest
	if err := json.Unmarshal(manData, &man); err != nil {
		return nil, "", fmt.Errorf("parse manifest: %w", err)
	}
	layers := make([]layerSrc, 0, len(man.Layers))
	for _, ld := range man.Layers {
		lp, err := blobPath(ld.Digest)
		if err != nil {
			return nil, "", err
		}
		layers = append(layers, tempLayer(ld.Digest, lp))
	}
	return layers, manDesc.Digest, nil
}

// firstImageManifest picks the first descriptor that looks like an image
// manifest (skipping nested indexes when a plain manifest is present).
func firstImageManifest(idx ociIndex) (ociDescriptor, error) {
	if len(idx.Manifests) == 0 {
		return ociDescriptor{}, errors.New("index has no manifests")
	}
	for _, d := range idx.Manifests {
		if strings.Contains(d.MediaType, "manifest") {
			return d, nil
		}
	}
	return idx.Manifests[0], nil
}

// tempLayer builds a layerSrc backed by a file path.
func tempLayer(name, p string) layerSrc {
	return layerSrc{name: name, open: func() (io.ReadCloser, error) {
		return os.Open(p) // #nosec G304 -- our own temp file or a path from the layout index
	}}
}

// blobKey maps a "sha256:hex" digest to its OCI archive path.
func blobKey(digest string) string {
	alg, hexv, ok := splitDigest(digest)
	if !ok {
		return ""
	}
	return "blobs/" + alg + "/" + hexv
}

func splitDigest(digest string) (alg, hexv string, ok bool) {
	alg, hexv, ok = strings.Cut(digest, ":")
	if !ok || alg == "" || hexv == "" {
		return "", "", false
	}
	// The algorithm and encoded parts of an OCI digest are strictly bounded by
	// the image spec: the algorithm is [a-z0-9]+ (with optional separators we
	// don't need) and, for the registered sha256/sha512 algorithms, the encoded
	// value is lowercase hex. Enforcing this is a security boundary — these
	// components are joined onto the filesystem in parseOCILayoutDir, so any
	// '/', '\', or '.' would enable directory traversal out of blobs/.
	if !isDigestAlg(alg) || !isHex(hexv) {
		return "", "", false
	}
	return alg, hexv, true
}

// isDigestAlg reports whether s is a valid OCI digest algorithm component
// ([a-z0-9]+) — notably free of any path separator.
func isDigestAlg(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// isHex reports whether s is non-empty and all hexadecimal digits.
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}
