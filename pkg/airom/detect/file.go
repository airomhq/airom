package detect

import (
	"context"
	"errors"
	"io"
	"path"
)

// ErrNotSeekable is returned by File.ReaderAt on sources that cannot
// provide random access (tar-stream image scans). A detector needing
// seekability declares a streaming fallback — the detectortest harness runs
// every detector against both backings to enforce it.
var ErrNotSeekable = errors.New("detect: source is not seekable")

// ReaderAtCloser is random access with explicit ownership: whoever obtains
// one closes it.
type ReaderAtCloser interface {
	io.ReaderAt
	io.Closer
}

// FileProviders supplies a File's lazy capabilities. The engine binds these
// to its read-once, tee-hashed file context; the detectortest harness binds
// them to fixtures. Any nil provider degrades gracefully (ReaderAt →
// ErrNotSeekable; hashes → unavailable).
type FileProviders struct {
	// Content performs the single bounded read: bytes, truncated, error.
	// Already context-bound by the creator.
	Content  func() ([]byte, bool, error)
	ReaderAt func() (ReaderAtCloser, error)
	SHA256   func() ([]byte, bool)
	XXH3     func() (uint64, bool)
}

// File is the read-once access handle a FileDetector receives. Not safe for
// concurrent use: all detectors for one file run sequentially in one worker
// (§8), which is what makes read-once lock-free.
//
// Buffer lifetime: Header() and Content() buffers are recycled when the
// worker finishes the file — copy out anything you retain (occurrence
// snippets are ≤200 bytes by contract, and the engine fills them for you).
type File struct {
	ref    FileRef
	header []byte
	p      FileProviders

	loaded    bool
	content   []byte
	truncated bool
	loadErr   error
}

// NewFile builds a File. Used by the engine's adapter and the detectortest
// harness; detectors only ever consume Files.
func NewFile(ref FileRef, header []byte, p FileProviders) *File {
	return &File{ref: ref, header: header, p: p}
}

// Ref returns the file's classified identity.
func (f *File) Ref() FileRef { return f.ref }

// Path returns the source-root-relative slash path.
func (f *File) Path() string { return f.ref.Path }

// Base returns the last path element.
func (f *File) Base() string { return path.Base(f.ref.Path) }

// Header returns the shared header sample (≤32 KB; the whole file when
// smaller).
func (f *File) Header() []byte { return f.header }

// Content performs THE single bounded, tee-hashed content read on first
// call and returns the same buffer afterwards (invariant P1). Check
// Truncated when byte-exact semantics matter: content may be a capped
// prefix.
func (f *File) Content() ([]byte, error) {
	if !f.loaded {
		f.loaded = true
		if f.p.Content == nil {
			f.loadErr = errors.New("detect: file has no content provider")
		} else {
			f.content, f.truncated, f.loadErr = f.p.Content()
		}
	}
	return f.content, f.loadErr
}

// Truncated reports whether Content returned a capped prefix. Meaningful
// after Content has been called.
func (f *File) Truncated() bool { return f.truncated }

// ReaderAt provides random access on seekable sources and ErrNotSeekable on
// streams. The caller owns the returned handle and must Close it. Prefer
// Content() — it is source-agnostic.
func (f *File) ReaderAt() (ReaderAtCloser, error) {
	if f.p.ReaderAt == nil {
		return nil, ErrNotSeekable
	}
	return f.p.ReaderAt()
}

// SHA256 returns the full-file digest when available (content read without
// truncation). The engine attaches it to assembled components automatically
// — detectors rarely need it directly.
func (f *File) SHA256() ([]byte, bool) {
	if f.p.SHA256 == nil {
		return nil, false
	}
	return f.p.SHA256()
}

// XXH3 returns the fast content hash of the bytes actually read, when
// available.
func (f *File) XXH3() (uint64, bool) {
	if f.p.XXH3 == nil {
		return 0, false
	}
	return f.p.XXH3()
}

// Resolver is the phase-2 pull API (§6.1): source-agnostic file queries
// honoring the same ignore rules as the walk — a project detector can never
// see a file phase 1 could not.
type Resolver interface {
	FilesByGlob(ctx context.Context, patterns ...string) ([]FileRef, error)
	Open(path string) (io.ReadCloser, error)
	Stat(path string) (FileRef, error)
}
