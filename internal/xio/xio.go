// Package xio provides the bounded-I/O primitives behind invariant P2
// (ARCHITECTURE.md §2, §8): a clamped byte-weighted semaphore separating
// heavy-I/O parallelism from CPU parallelism, and pooled buffers so content
// reads never allocate per file. The spool (memory -> tmpfile overflow for
// stream sources) joins this package with the image source in Phase 6.
package xio

import (
	"context"
	"sync"

	"golang.org/x/sync/semaphore"
)

// Weighted is a byte-weighted semaphore with CLAMPED acquisition: a request
// larger than the total budget acquires the whole budget instead of blocking
// forever. Without the clamp, hashing a 40 GB GGUF against a 256 MiB budget
// is a guaranteed deadlock (ARCHITECTURE.md §8; contract-tested).
type Weighted struct {
	sem      *semaphore.Weighted
	capacity int64
}

// NewWeighted returns a semaphore with the given byte budget. A non-positive
// capacity yields a no-op semaphore (unlimited).
func NewWeighted(capacity int64) *Weighted {
	if capacity <= 0 {
		return &Weighted{}
	}
	return &Weighted{sem: semaphore.NewWeighted(capacity), capacity: capacity}
}

// Acquire reserves min(n, capacity) bytes, blocking until available or ctx
// is done. It returns an idempotent release function. n <= 0 acquires
// nothing and returns a no-op release.
func (w *Weighted) Acquire(ctx context.Context, n int64) (release func(), err error) {
	if w.sem == nil || n <= 0 {
		return func() {}, nil
	}
	if n > w.capacity {
		n = w.capacity // the clamp: never request more than exists
	}
	if err := w.sem.Acquire(ctx, n); err != nil {
		return func() {}, err
	}
	var once sync.Once
	return func() { once.Do(func() { w.sem.Release(n) }) }, nil
}

// BufPool is a sync.Pool of fixed-capacity byte slices. One pool per size
// class; buffers are recycled when a worker finishes a file (consumers must
// copy out anything they retain — filectx documents this contract).
type BufPool struct {
	pool sync.Pool
	size int
}

// NewBufPool returns a pool of buffers with the given capacity.
func NewBufPool(size int) *BufPool {
	p := &BufPool{size: size}
	p.pool.New = func() any {
		b := make([]byte, size)
		return &b
	}
	return p
}

// Get returns a buffer of the pool's full length. Contents are undefined.
func (p *BufPool) Get() []byte {
	return *(p.pool.Get().(*[]byte))
}

// Put recycles a buffer obtained from Get. Buffers of the wrong capacity
// (e.g. re-sliced beyond recognition) are dropped rather than poisoning the
// pool.
func (p *BufPool) Put(b []byte) {
	if cap(b) != p.size {
		return
	}
	b = b[:p.size]
	p.pool.Put(&b)
}

// Size returns the pool's buffer size in bytes.
func (p *BufPool) Size() int { return p.size }
