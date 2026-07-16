package source

import (
	"context"
	"io"

	"github.com/Roro1727/airom/internal/classify"
)

// Kind identifies a source implementation (ARCHITECTURE.md §7).
type Kind string

// The four §7 source kinds. Dir is implemented in Phase 4; repo, image, and
// k8s land in Phase 6 (repo delegates to dir after a shallow clone).
const (
	KindDir   Kind = "dir"
	KindRepo  Kind = "repo"
	KindImage Kind = "image"
	KindK8s   Kind = "k8s"
)

// ReaderAtCloser is random access with explicit ownership: whoever obtains
// one closes it.
type ReaderAtCloser interface {
	io.ReaderAt
	io.Closer
}

// Entry is one enumerated file: classified identity plus lazy content
// access. For dir sources Open is reusable and ReaderAt is available; for
// stream sources Open is one-shot (spool-backed) and ReaderAt is nil.
type Entry struct {
	Ref      classify.FileRef
	Open     func() (io.ReadCloser, error)
	ReaderAt func() (ReaderAtCloser, error)
}

// WalkFunc receives entries during a streaming walk. Returning an error
// aborts the walk with that error. The callback may be invoked from
// multiple goroutines (fastwalk); the engine's task channel serializes
// downstream.
type WalkFunc func(Entry) error

// Unknown records a file or directory the walk could not fully process
// (permission denied, races, IO errors) — surfaced in the output, never
// silently dropped (invariant P6).
type Unknown struct {
	Path   string
	Stage  string // "walk", "stat", ...
	Reason string
}

// Info is the provenance root for a scan's output (§7). Phase 6 sources
// extend it with git/image/k8s fields.
type Info struct {
	Kind   Kind
	Target string
}

// Source is the engine-facing contract every acquisition implements (§7).
type Source interface {
	Name() string
	Kind() Kind
	// ID is the source's content identity (dir realpath; later: image
	// digest, git HEAD) — a cache-key ingredient.
	ID() string
	// Walk streams entries (ignore-aware, files only). It returns after
	// every callback has returned; walk-level failures are recorded as
	// Unknowns, not errors (P6) — the returned error is reserved for
	// cancellation and catastrophic source failure.
	Walk(ctx context.Context, fn WalkFunc) error
	// WalkUnknowns returns the walk-level Unknown records accumulated by
	// the most recent Walk. Valid after Walk returns.
	WalkUnknowns() []Unknown
	// Resolver is the pull-style query API for phase-2 project detectors.
	Resolver() Resolver
	Info() Info
	Close() error
}

// Resolver is the pull-side file query API (§6.1, §7). Paths are
// source-root-relative with forward slashes. Implementations honor the same
// ignore rules as Walk.
type Resolver interface {
	FilesByGlob(ctx context.Context, patterns ...string) ([]classify.FileRef, error)
	Open(path string) (io.ReadCloser, error)
	Stat(path string) (classify.FileRef, error)
}
