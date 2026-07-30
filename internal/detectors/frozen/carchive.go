// Package frozen reads Python applications that were frozen into a single
// executable, where the usual evidence does not exist on disk.
//
// A PyInstaller onefile build compiles every module into a compressed PYZ
// archive appended to the bootloader: no .py, no .pyc, and usually no
// dist-info. Source rules match imports and manifest detectors read metadata
// files, so both find exactly nothing — a 197 MB binary bundling crawl4ai,
// agno, fastmcp, litellm, and firecrawl scans as containing no AI at all.
//
// Nothing here executes or unmarshals a code object. The PYZ's directory is a
// marshaled dict, and only the handful of marshal types that dict can contain
// are implemented; a code object is skipped rather than decoded. That is partly
// because the frozen interpreter's version rarely matches the one this binary
// was built against, and mostly because marshal was never designed to be fed
// untrusted input.
package frozen

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// cookieMagic ends every PyInstaller CArchive.
var cookieMagic = []byte{'M', 'E', 'I', 0o14, 0o13, 0o12, 0o13, 0o16}

const (
	// cookieLen is struct '!8sIIII64s': magic, pkgLen, tocPos, tocLen, pyVers,
	// pyLibName.
	cookieLen = 8 + 4 + 4 + 4 + 4 + 64

	// cookieSearch is how far back from EOF the cookie is looked for. It is
	// normally the very last bytes, but a signed or padded binary can carry an
	// overlay after it.
	cookieSearch = 1 << 20

	// tocEntryHeader is struct '!iIIIBc': entryLen, offset, dLen, uLen, flag,
	// typeCode — followed by a NUL-padded name filling out entryLen.
	tocEntryHeader = 4 + 4 + 4 + 4 + 1 + 1

	// maxTOCBytes and maxEntries bound what a malformed or hostile header can
	// make this allocate. A real onefile TOC is tens of KB.
	maxTOCBytes = 64 << 20
	maxEntries  = 500_000

	// maxEntryBytes bounds one decompressed member. PYZ archives in the wild
	// are a few tens of MB; anything larger is not something to inflate into
	// memory on the strength of a length field.
	maxEntryBytes = 256 << 20
)

// errNotFrozen means the file carries no CArchive cookie. It is the common
// case for every executable on a machine and never worth reporting.
var errNotFrozen = errors.New("frozen: no PyInstaller CArchive cookie")

// TOC type codes that matter here.
const (
	typePYZ       = 'z' // a PYZ archive (lowercase in current PyInstaller)
	typePYZUpper  = 'Z' // older builds
	typeData      = 'x' // arbitrary data, which is how dist-info files ride along
	typeDataUpper = 'X'
)

// Entry is one CArchive member.
type Entry struct {
	Name       string
	Offset     int64 // absolute, already rebased onto the archive start
	Compressed int64
	Plain      int64
	Deflated   bool
	Type       byte
}

// IsPYZ reports whether this entry is the frozen module archive.
func (e Entry) IsPYZ() bool { return e.Type == typePYZ || e.Type == typePYZUpper }

// IsData reports whether this entry is a bundled data file (dist-info lands here).
func (e Entry) IsData() bool { return e.Type == typeData || e.Type == typeDataUpper }

// Archive is a parsed CArchive directory. It holds no file bytes: members are
// read on demand through the same ReaderAt, so a 197 MB executable costs a few
// seeks rather than a 197 MB read.
type Archive struct {
	r       io.ReaderAt
	Entries []Entry
}

// ReadArchive locates and parses the CArchive directory of a frozen binary.
// size is the file's length. It returns errNotFrozen for any ordinary
// executable, which is the overwhelmingly common answer.
func ReadArchive(r io.ReaderAt, size int64) (*Archive, error) {
	if size < cookieLen {
		return nil, errNotFrozen
	}
	// Search a window at the end rather than assuming the cookie is the final
	// bytes: code signing and installers append their own trailers.
	window := int64(cookieSearch)
	if window > size {
		window = size
	}
	tail := make([]byte, window)
	if _, err := r.ReadAt(tail, size-window); err != nil && !errors.Is(err, io.EOF) {
		return nil, errNotFrozen
	}
	idx := bytes.LastIndex(tail, cookieMagic)
	if idx < 0 || int64(idx)+cookieLen > window {
		return nil, errNotFrozen
	}
	cookie := tail[idx : idx+cookieLen]
	cookieAt := size - window + int64(idx)

	pkgLen := int64(binary.BigEndian.Uint32(cookie[8:12]))
	tocPos := int64(binary.BigEndian.Uint32(cookie[12:16]))
	tocLen := int64(binary.BigEndian.Uint32(cookie[16:20]))

	// The archive is appended to the bootloader, so every offset inside it is
	// relative to where the archive starts — which is derived from the cookie's
	// own position and the package length, NOT from the start of the file.
	archiveStart := cookieAt + cookieLen - pkgLen
	if archiveStart < 0 || tocLen <= 0 || tocLen > maxTOCBytes {
		return nil, fmt.Errorf("frozen: implausible archive header (start=%d tocLen=%d)", archiveStart, tocLen)
	}
	tocAt := archiveStart + tocPos
	if tocAt < 0 || tocAt+tocLen > size {
		return nil, fmt.Errorf("frozen: TOC at %d+%d lies outside a %d-byte file", tocAt, tocLen, size)
	}

	toc := make([]byte, tocLen)
	if _, err := r.ReadAt(toc, tocAt); err != nil {
		return nil, fmt.Errorf("frozen: read TOC: %w", err)
	}
	entries, err := parseTOC(toc, archiveStart, size)
	if err != nil {
		return nil, err
	}
	return &Archive{r: r, Entries: entries}, nil
}

// parseTOC walks the packed directory.
func parseTOC(toc []byte, archiveStart, size int64) ([]Entry, error) {
	var out []Entry
	for pos := 0; pos+tocEntryHeader <= len(toc); {
		// #nosec G115 -- the TOC field IS a signed int32 ('!i'), so the wrap is
		// the correct reading of it; a negative or non-advancing length is
		// rejected on the next line rather than trusted.
		entryLen := int(int32(binary.BigEndian.Uint32(toc[pos : pos+4])))
		// A non-advancing or negative length would loop forever; a length past
		// the buffer is truncation. Both end the walk with what we have.
		if entryLen < tocEntryHeader || pos+entryLen > len(toc) {
			break
		}
		e := Entry{
			Offset:     archiveStart + int64(binary.BigEndian.Uint32(toc[pos+4:pos+8])),
			Compressed: int64(binary.BigEndian.Uint32(toc[pos+8 : pos+12])),
			Plain:      int64(binary.BigEndian.Uint32(toc[pos+12 : pos+16])),
			Deflated:   toc[pos+16] != 0,
			Type:       toc[pos+17],
			Name:       string(bytes.TrimRight(toc[pos+tocEntryHeader:pos+entryLen], "\x00")),
		}
		// Drop members that do not lie inside the file rather than trusting the
		// length fields at read time.
		if e.Offset >= 0 && e.Compressed >= 0 && e.Offset+e.Compressed <= size {
			out = append(out, e)
		}
		pos += entryLen
		if len(out) > maxEntries {
			break
		}
	}
	if len(out) == 0 {
		return nil, errors.New("frozen: CArchive TOC held no usable entries")
	}
	return out, nil
}

// Read returns one member's bytes, inflating it when the archive stored it
// compressed.
func (a *Archive) Read(e Entry) ([]byte, error) {
	if e.Compressed <= 0 || e.Compressed > maxEntryBytes {
		return nil, fmt.Errorf("frozen: entry %q has an unusable length %d", e.Name, e.Compressed)
	}
	raw := make([]byte, e.Compressed)
	if _, err := a.r.ReadAt(raw, e.Offset); err != nil {
		return nil, fmt.Errorf("frozen: read %q: %w", e.Name, err)
	}
	if !e.Deflated {
		return raw, nil
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("frozen: inflate %q: %w", e.Name, err)
	}
	defer func() { _ = zr.Close() }()
	// Cap the inflated size: the stored "plain" length is attacker-controlled,
	// so it bounds the read rather than sizing an allocation up front.
	limit := e.Plain
	if limit <= 0 || limit > maxEntryBytes {
		limit = maxEntryBytes
	}
	out, err := io.ReadAll(io.LimitReader(zr, limit))
	if err != nil {
		return nil, fmt.Errorf("frozen: inflate %q: %w", e.Name, err)
	}
	return out, nil
}

// inflateMaybe zlib-decompresses b, returning it untouched when it is not a
// zlib stream. PYZ members are individually compressed, but not in every build.
func inflateMaybe(b []byte) []byte {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return b
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, maxEntryBytes))
	if err != nil || len(out) == 0 {
		return b
	}
	return out
}
