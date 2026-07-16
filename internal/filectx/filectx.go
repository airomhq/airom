// Package filectx implements the read-once file access contract
// (ARCHITECTURE.md §8, invariant P1): each file's bytes are read from the
// source at most once, every interested consumer shares that single buffer,
// and the content hashes (xxh3 for the cache content-key, SHA-256 for BOM
// integrity) are tee-computed during that same read — never a second pass.
package filectx

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/zeebo/xxh3"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/xio"
)

// HeaderSize is the shared header sample length: large enough for magic
// sniffing, binary detection, and small-header parsing; small enough to be
// free (ARCHITECTURE.md §3).
const HeaderSize = 32 * 1024

// ErrNotSeekable is returned by ReaderAt on sources that cannot provide
// random access (tar streams). The asymmetry between dir and stream sources
// is explicit in the API rather than papered over: a detector that needs
// seeking declares a streaming fallback (ARCHITECTURE.md §6.1, §7).
var ErrNotSeekable = errors.New("filectx: source is not seekable")

// Opener yields the file's content stream. For dir sources it is reusable;
// for stream sources it is one-shot (spool-backed).
type Opener func() (io.ReadCloser, error)

// File is the read-once access handle handed to detectors. Not safe for
// concurrent use: all detectors for one file run sequentially in one worker
// (ARCHITECTURE.md §8), which is what makes read-once free of locks.
//
// Buffer lifetime: Header() and Content() buffers are pooled and recycled
// when the worker finishes the file. Consumers must copy out anything they
// retain (snippets are ≤200 bytes by contract).
type File struct {
	Ref classify.FileRef

	header   []byte
	open     Opener
	readerAt func() (ReaderAtCloser, error) // nil => ErrNotSeekable

	contentCap int64
	ioGate     *xio.Weighted
	pool       *xio.BufPool

	// read-once state
	loaded    bool
	content   []byte
	pooledBuf []byte // what we borrowed from pool (returned on Release)
	truncated bool
	loadErr   error
	xxh       uint64
	sha       []byte
	bytesRead int64
}

// ReaderAtCloser mirrors source.ReaderAtCloser without importing it
// (filectx sits below source in the dependency order).
type ReaderAtCloser interface {
	io.ReaderAt
	io.Closer
}

// Options configures a File.
type Options struct {
	ContentCap int64         // max bytes Content will read (0 = no cap)
	IOGate     *xio.Weighted // byte-weighted gate for large reads (nil = ungated)
	Pool       *xio.BufPool  // content buffer pool (nil = allocate)
	ReaderAt   func() (ReaderAtCloser, error)
}

// New builds a File over a pre-read header sample and a lazy opener.
// header may be shorter than HeaderSize for small files; it must remain
// valid until Release.
func New(ref classify.FileRef, header []byte, open Opener, opts Options) *File {
	return &File{
		Ref:        ref,
		header:     header,
		open:       open,
		readerAt:   opts.ReaderAt,
		contentCap: opts.ContentCap,
		ioGate:     opts.IOGate,
		pool:       opts.Pool,
	}
}

// Header returns the shared header sample (≤ HeaderSize bytes; the whole
// file when smaller). Never nil for a successfully opened file.
func (f *File) Header() []byte { return f.header }

// Content performs THE single bounded content read on first call and
// returns the same buffer afterwards. The read is tee-hashed: XXH3 and
// SHA-256 become available at no extra pass. truncated reports that the
// file exceeded the cap and content holds only the prefix.
func (f *File) Content(ctx context.Context) (content []byte, truncated bool, err error) {
	if f.loaded {
		return f.content, f.truncated, f.loadErr
	}
	f.loaded = true
	f.loadErr = f.load(ctx)
	return f.content, f.truncated, f.loadErr
}

func (f *File) load(ctx context.Context) error {
	want := f.Ref.Size
	if f.contentCap > 0 && want > f.contentCap {
		want = f.contentCap
		f.truncated = true
	}

	// Gate large reads on the byte-weighted semaphore so heavy I/O
	// parallelism is a separate knob from CPU parallelism (§8). The gate
	// clamps internally, so a file larger than the whole budget still
	// proceeds — serially.
	if f.ioGate != nil && want > 1<<20 {
		release, err := f.ioGate.Acquire(ctx, want)
		if err != nil {
			return err
		}
		defer release()
	}

	rc, err := f.open()
	if err != nil {
		return fmt.Errorf("open %s: %w", f.Ref.Path, err)
	}
	defer func() { _ = rc.Close() }()

	buf := f.borrow(int(want))
	n, err := io.ReadFull(rc, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read %s: %w", f.Ref.Path, err)
	}
	f.content = buf[:n]
	f.bytesRead = int64(n)

	// The truncated flag must reflect the STREAM, not the stat: a file may
	// have shrunk (we hash what we read — fine) or GROWN between the
	// walker's stat and this read (stat-sized prefix would silently
	// masquerade as the whole file). Whenever the read filled everything we
	// asked for, a cheap single-byte probe decides honestly.
	f.truncated = false
	if n == len(buf) {
		var probe [1]byte
		if m, _ := rc.Read(probe[:]); m > 0 {
			f.truncated = true
		}
	}

	// Tee-hash the bytes detectors will actually see. The cache content-key
	// is (xxh3, size, truncated): findings are a pure function of exactly
	// those inputs, so the key is exact even for capped reads (§10).
	f.xxh = xxh3.Hash(f.content)
	if !f.truncated {
		sum := sha256.Sum256(f.content)
		f.sha = sum[:]
	}
	return nil
}

func (f *File) borrow(n int) []byte {
	if f.pool != nil && n <= f.pool.Size() {
		f.pooledBuf = f.pool.Get()
		return f.pooledBuf[:n]
	}
	return make([]byte, n)
}

// XXH3 returns the xxh3 of the content actually read (the cache content-key
// ingredient). ok is false before Content has been called successfully.
func (f *File) XXH3() (v uint64, ok bool) {
	return f.xxh, f.loaded && f.loadErr == nil
}

// SHA256 returns the full-file SHA-256, available only when the content was
// read without truncation (a prefix hash must never masquerade as a file
// hash; large model files are hashed streaming by their detectors instead).
func (f *File) SHA256() (sum []byte, ok bool) {
	return f.sha, f.sha != nil
}

// Truncated reports whether Content returned a capped prefix.
func (f *File) Truncated() bool { return f.truncated }

// BytesRead returns the number of content bytes read (for ScanStats).
func (f *File) BytesRead() int64 { return f.bytesRead }

// ReaderAt provides random access on seekable sources and ErrNotSeekable on
// streams. The caller owns the returned handle and must Close it.
func (f *File) ReaderAt() (ReaderAtCloser, error) {
	if f.readerAt == nil {
		return nil, ErrNotSeekable
	}
	return f.readerAt()
}

// Release returns pooled buffers. The File and every buffer it handed out
// are invalid afterwards. Called by the engine when all detectors for the
// file have run.
func (f *File) Release() {
	if f.pooledBuf != nil && f.pool != nil {
		f.pool.Put(f.pooledBuf)
		f.pooledBuf = nil
	}
	f.content = nil
}
