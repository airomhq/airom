// Package imagesource implements the container-image Source (ARCHITECTURE.md
// §7). It resolves a squashed root filesystem from a container image and
// streams its files through the standard source contract.
//
// # Spooling and memory bounds (invariant P2)
//
// The squashed filesystem is produced by applying an image's layers top→base
// with whiteout/opaque resolution, exactly once. Because the underlying tar
// streams are consume-once, each effective file's bytes are captured (spooled)
// during that single pass so Entry.Open and the phase-2 Resolver can serve
// them afterward. Spooling is strictly bounded:
//
//   - Files up to MaxMemPerFile (default 4 MiB) are held in memory, subject to
//     a global MemBudget (default 256 MiB).
//   - Larger files, or files that would exceed MemBudget, spill to a temp file
//     up to MaxDiskPerFile (default 64 MiB), subject to a global DiskBudget
//     (default 2 GiB).
//   - Files exceeding those caps are surfaced header-only: Entry.Open returns
//     just the first HeaderCap bytes (default 64 KiB), enough for magic/header
//     detectors, with the remainder discarded. Content-based detectors see a
//     truncated read.
//
// Memory and disk therefore stay bounded regardless of image size or content.
// Entry.ReaderAt always reports ErrNotSeekable — spooled streams are not
// randomly seekable through the contract.
//
// # Deviation from the original design
//
// The design called for go-containerregistry (remote.Image / daemon.Image /
// mutate.Extract). That library's transitive dependencies
// (opencontainers/*, klauspost/compress, ...) are absent from this module's
// go.sum, and the build constraints for this work forbid `go get`/`go mod`.
// This package therefore reads images with the standard library instead:
// docker-save archives, OCI image-layout archives, and OCI layout directories,
// with gzip and uncompressed layers. Consequences:
//
//   - New(ref) for a live registry or docker-daemon pull is NOT implemented;
//     it accepts a local archive/layout path (delegating to NewFromTar) and
//     otherwise returns a clear error.
//   - zstd-compressed layers are unsupported (recorded as an Unknown).
//
// Once go-containerregistry is wired into go.mod, resolution can be swapped to
// mutate.Extract without changing the spooling/Walk/Resolver machinery below.
package imagesource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/source"
)

// ErrNotSeekable is returned by Entry.ReaderAt: image files are served from a
// consume-once spool and are not randomly seekable through the contract.
var ErrNotSeekable = errors.New("imagesource: entries are not seekable (stream-backed)")

// Default spool bounds.
const (
	defaultMaxMemPerFile  = 4 << 20   // 4 MiB
	defaultMaxDiskPerFile = 64 << 20  // 64 MiB
	defaultMemBudget      = 256 << 20 // 256 MiB
	defaultDiskBudget     = 2 << 30   // 2 GiB
	defaultHeaderCap      = 64 << 10  // 64 KiB
)

// Options configures an image source.
type Options struct {
	// IgnoreGlobs are user --ignore doublestar patterns over image-root paths.
	IgnoreGlobs []string

	// Spool bounds; any zero field takes its default.
	MaxMemPerFile  int64
	MaxDiskPerFile int64
	MemBudget      int64
	DiskBudget     int64
	HeaderCap      int64

	// TmpDir is where spill/temporary files are created (default os.TempDir()).
	TmpDir string
}

func (o *Options) withDefaults() {
	if o.MaxMemPerFile <= 0 {
		o.MaxMemPerFile = defaultMaxMemPerFile
	}
	if o.MaxDiskPerFile <= 0 {
		o.MaxDiskPerFile = defaultMaxDiskPerFile
	}
	if o.MemBudget <= 0 {
		o.MemBudget = defaultMemBudget
	}
	if o.DiskBudget <= 0 {
		o.DiskBudget = defaultDiskBudget
	}
	if o.HeaderCap <= 0 {
		o.HeaderCap = defaultHeaderCap
	}
}

// Source is the image implementation of source.Source.
type Source struct {
	target string
	opts   Options

	once   sync.Once
	matErr error

	// Effective filesystem after squashing, built once by materialize().
	ordered []*fileEntry
	byPath  map[string]*fileEntry
	id      string // image digest ("sha256:..."), else the target

	mu       sync.Mutex
	unknowns []source.Unknown

	// Resource accounting; guarded by mu.
	memUsed  int64
	diskUsed int64
	tmpDir   string // dedicated temp dir holding all spill/staging files
}

var _ source.Source = (*Source)(nil)

// fileEntry is one effective file in the squashed filesystem.
type fileEntry struct {
	ref classify.FileRef
	sp  *spooled
}

// spooled holds a file's captured bytes: fully in memory, fully on disk, or
// (for oversized files) only a header prefix.
type spooled struct {
	mem     []byte // full content in memory
	tmpPath string // full content on disk
	header  []byte // header-only prefix (content truncated)
}

// open returns a fresh reader over the spooled bytes.
func (s *spooled) open() (io.ReadCloser, error) {
	switch {
	case s.mem != nil:
		return io.NopCloser(bytes.NewReader(s.mem)), nil
	case s.tmpPath != "":
		return os.Open(s.tmpPath) // #nosec G304 -- our own spill file under tmpDir
	default:
		// Header-only: serve the captured prefix; the remainder was discarded.
		return io.NopCloser(bytes.NewReader(s.header)), nil
	}
}

// New prepares an image source from ref.
//
// Because live registry/daemon resolution is not wired in (see the package
// doc), ref must be a local path to a container-image archive (docker-save or
// OCI image-layout tar) or an OCI layout directory. Anything else returns an
// error directing the caller to supply such a path.
func New(ref string, opts Options) (*Source, error) {
	if ref == "" {
		return nil, fmt.Errorf("image source: empty reference")
	}
	if _, err := os.Stat(ref); err == nil {
		return NewFromTar(ref, opts)
	}
	return nil, fmt.Errorf("image source %q: live registry/daemon pulls are not available in this build; "+
		"supply a local image archive (docker save -o img.tar ...) or an OCI layout path", ref)
}

// NewFromTar prepares an image source from a docker-save/OCI-archive tar file
// or an OCI image-layout directory at path.
func NewFromTar(path string, opts Options) (*Source, error) {
	opts.withDefaults()
	// Fail fast on a missing path; the heavy squash still happens lazily under
	// sync.Once on first Walk/Resolver use.
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("image source %q: %w", path, err)
	}
	return &Source{
		target: path,
		opts:   opts,
		byPath: map[string]*fileEntry{},
		id:     "image:" + path,
	}, nil
}

// Name returns the image target (archive path or reference).
func (s *Source) Name() string { return s.target }

// Kind reports the source kind ("image").
func (s *Source) Kind() source.Kind { return source.KindImage }

// ID is the content identity: the image/manifest digest when resolvable.
func (s *Source) ID() string {
	if err := s.ensure(); err != nil {
		return "image:" + s.target
	}
	return s.id
}

// Info returns the provenance root for the scan output.
func (s *Source) Info() source.Info { return source.Info{Kind: source.KindImage, Target: s.target} }

// ensure runs the one-time squash+spool, memoizing any error.
func (s *Source) ensure() error {
	s.once.Do(func() { s.matErr = s.materialize() })
	return s.matErr
}

// Walk streams the squashed filesystem's regular files. Materialization
// (squash + spool) happens once here or via the Resolver; a materialization
// failure is a source-acquisition error (fatal), while per-file/per-layer
// problems degrade to Unknowns (invariant P6).
func (s *Source) Walk(ctx context.Context, fn source.WalkFunc) error {
	if err := s.ensure(); err != nil {
		return err
	}
	for _, fe := range s.ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.userIgnored(fe.ref.Path) {
			continue
		}
		if err := fn(source.Entry{
			Ref:      fe.ref,
			Open:     fe.sp.open,
			ReaderAt: func() (source.ReaderAtCloser, error) { return nil, ErrNotSeekable },
		}); err != nil {
			return err
		}
	}
	return nil
}

// WalkUnknowns returns the Unknown records accumulated during materialization
// (unreadable/whiteout-inconsistent/zstd layers, oversized truncations).
func (s *Source) WalkUnknowns() []source.Unknown {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]source.Unknown(nil), s.unknowns...)
}

func (s *Source) record(pathStr, stage, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unknowns = append(s.unknowns, source.Unknown{Path: pathStr, Stage: stage, Reason: reason})
}

func (s *Source) userIgnored(rel string) bool {
	for _, g := range s.opts.IgnoreGlobs {
		if ok, _ := doublestar.Match(g, rel); ok {
			return true
		}
	}
	return false
}

// Close releases spooled resources (delegates to Clean).
func (s *Source) Close() error { return s.Clean() }

// Clean removes all temp files/dirs created for spilling and layer staging.
func (s *Source) Clean() error {
	s.mu.Lock()
	dir := s.tmpDir
	s.tmpDir = ""
	s.diskUsed = 0
	s.mu.Unlock()
	if dir == "" {
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("imagesource: clean temp dir: %w", err)
	}
	return nil
}

// ── Resolver: pull-side query over the spooled filesystem ───────────────────

// Resolver returns the phase-2 query API. It serves fully-spooled files;
// header-only (oversized) files are visible to Stat/FilesByGlob but Open
// yields only their header prefix.
func (s *Source) Resolver() source.Resolver { return &resolver{s: s} }

type resolver struct{ s *Source }

func (r *resolver) FilesByGlob(_ context.Context, patterns ...string) ([]classify.FileRef, error) {
	for _, p := range patterns {
		if !doublestar.ValidatePattern(p) {
			return nil, fmt.Errorf("invalid glob %q", p)
		}
	}
	if err := r.s.ensure(); err != nil {
		return nil, err
	}
	var out []classify.FileRef
	for _, fe := range r.s.ordered {
		if r.s.userIgnored(fe.ref.Path) {
			continue
		}
		for _, p := range patterns {
			if ok, _ := doublestar.Match(p, fe.ref.Path); ok {
				out = append(out, fe.ref)
				break
			}
		}
	}
	return out, nil
}

func (r *resolver) Open(rel string) (io.ReadCloser, error) {
	if err := r.s.ensure(); err != nil {
		return nil, err
	}
	rel = normalizeName(rel)
	fe, ok := r.s.byPath[rel]
	if !ok || r.s.userIgnored(rel) {
		return nil, fmt.Errorf("open %q: not found in image", rel)
	}
	return fe.sp.open()
}

func (r *resolver) Stat(rel string) (classify.FileRef, error) {
	if err := r.s.ensure(); err != nil {
		return classify.FileRef{}, err
	}
	rel = normalizeName(rel)
	fe, ok := r.s.byPath[rel]
	if !ok || r.s.userIgnored(rel) {
		return classify.FileRef{}, fmt.Errorf("stat %q: not found in image", rel)
	}
	return fe.ref, nil
}
