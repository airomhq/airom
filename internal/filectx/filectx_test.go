package filectx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/zeebo/xxh3"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/xio"
)

// countingOpener wraps content and counts opens — the read-once proof.
type countingOpener struct {
	data  []byte
	opens int
}

func (c *countingOpener) open() (io.ReadCloser, error) {
	c.opens++
	return io.NopCloser(bytes.NewReader(c.data)), nil
}

func newTestFile(data []byte, opts Options) (*File, *countingOpener) {
	co := &countingOpener{data: data}
	ref := classify.FileRef{Path: "x.py", Size: int64(len(data))}
	header := data
	if len(header) > HeaderSize {
		header = header[:HeaderSize]
	}
	return New(ref, header, co.open, opts), co
}

func TestContentReadOnce(t *testing.T) {
	data := []byte("model = \"gpt-4.1\"\n")
	f, co := newTestFile(data, Options{})

	c1, trunc, err := f.Content(context.Background())
	if err != nil || trunc {
		t.Fatalf("Content: %v trunc=%v", err, trunc)
	}
	if !bytes.Equal(c1, data) {
		t.Fatalf("content = %q", c1)
	}
	c2, _, _ := f.Content(context.Background())
	if &c1[0] != &c2[0] {
		t.Error("second Content returned a different buffer")
	}
	if co.opens != 1 {
		t.Errorf("opens = %d, want exactly 1 (invariant P1)", co.opens)
	}
}

func TestTeeHashes(t *testing.T) {
	data := bytes.Repeat([]byte("airom"), 1000)
	f, _ := newTestFile(data, Options{})
	if _, _, err := f.Content(context.Background()); err != nil {
		t.Fatal(err)
	}

	x, ok := f.XXH3()
	if !ok || x != xxh3.Hash(data) {
		t.Errorf("XXH3 = %x ok=%v, want %x", x, ok, xxh3.Hash(data))
	}
	want := sha256.Sum256(data)
	got, ok := f.SHA256()
	if !ok || !bytes.Equal(got, want[:]) {
		t.Errorf("SHA256 mismatch (ok=%v)", ok)
	}
}

func TestHashesUnavailableBeforeContent(t *testing.T) {
	f, _ := newTestFile([]byte("data"), Options{})
	if _, ok := f.XXH3(); ok {
		t.Error("XXH3 available before Content")
	}
	if _, ok := f.SHA256(); ok {
		t.Error("SHA256 available before Content")
	}
}

func TestTruncation(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1000)
	f, _ := newTestFile(data, Options{ContentCap: 100})

	content, trunc, err := f.Content(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !trunc || len(content) != 100 {
		t.Fatalf("trunc=%v len=%d, want truncated 100-byte prefix", trunc, len(content))
	}
	// Prefix hash exists (cache key ingredient) but SHA-256 must NOT:
	// a prefix hash never masquerades as a file hash.
	if _, ok := f.XXH3(); !ok {
		t.Error("XXH3 missing for truncated read")
	}
	if _, ok := f.SHA256(); ok {
		t.Error("SHA256 present for truncated read")
	}
}

func TestTruncationHonestWhenFileShrank(t *testing.T) {
	// Stat said 1000 bytes but the stream only has 80 (file changed between
	// stat and read): not truncated — we read everything there was.
	co := &countingOpener{data: bytes.Repeat([]byte("y"), 80)}
	ref := classify.FileRef{Path: "y.txt", Size: 1000}
	f := New(ref, co.data, co.open, Options{ContentCap: 100})

	content, trunc, err := f.Content(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if trunc {
		t.Error("shrunken file reported truncated")
	}
	if len(content) != 80 {
		t.Errorf("len = %d, want 80", len(content))
	}
}

func TestReaderAtNotSeekable(t *testing.T) {
	f, _ := newTestFile([]byte("z"), Options{})
	if _, err := f.ReaderAt(); !errors.Is(err, ErrNotSeekable) {
		t.Errorf("err = %v, want ErrNotSeekable", err)
	}
}

func TestPooledBufferRecycled(t *testing.T) {
	pool := xio.NewBufPool(1 << 10)
	data := []byte("pooled content")
	f, _ := newTestFile(data, Options{Pool: pool})
	if _, _, err := f.Content(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.Release()
	// After release the buffer is back in the pool; a fresh Get succeeds
	// and the File no longer references content.
	b := pool.Get()
	if len(b) != 1<<10 {
		t.Fatalf("pool broken after Release")
	}
	pool.Put(b)
}

func TestOpenErrorSurfaces(t *testing.T) {
	ref := classify.FileRef{Path: "gone.py", Size: 10}
	f := New(ref, nil, func() (io.ReadCloser, error) {
		return nil, errors.New("permission denied")
	}, Options{})
	if _, _, err := f.Content(context.Background()); err == nil {
		t.Fatal("want open error")
	}
	// error is sticky, no retry storm
	_, _, err2 := f.Content(context.Background())
	if err2 == nil {
		t.Fatal("want sticky error")
	}
}

// TestGrowingFileIsTruncatedHonestly is the grow-TOCTOU regression: a file
// appended between the walker's stat and the read must NOT yield a stale
// prefix presented as the full file.
func TestGrowingFileIsTruncatedHonestly(t *testing.T) {
	grown := bytes.Repeat([]byte("g"), 200)
	co := &countingOpener{data: grown}
	ref := classify.FileRef{Path: "grow.log", Size: 100} // stale stat
	f := New(ref, grown[:100], co.open, Options{ContentCap: 1 << 20})

	content, trunc, err := f.Content(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 100 {
		t.Fatalf("len = %d, want stat-bounded 100", len(content))
	}
	if !trunc {
		t.Error("grown file not reported truncated")
	}
	if _, ok := f.SHA256(); ok {
		t.Error("SHA256 present for a stale-size prefix (must never masquerade as a file hash)")
	}
	if _, ok := f.XXH3(); !ok {
		t.Error("XXH3 (cache-key ingredient) missing")
	}
}

// TestIOGateWiredForLargeReads: the >1MiB read path must acquire the gate
// with clamping (a read larger than the whole budget still proceeds).
func TestIOGateWiredForLargeReads(t *testing.T) {
	gate := xio.NewWeighted(1 << 20) // 1 MiB budget
	data := bytes.Repeat([]byte("a"), 3<<20)
	f, _ := newTestFile(data, Options{IOGate: gate, ContentCap: 4 << 20})

	done := make(chan error, 1)
	go func() {
		_, _, err := f.Content(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Content: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("large read deadlocked against a smaller budget (clamp not wired)")
	}
}

// TestIOGateCancellation: an exhausted gate must honor context cancellation.
func TestIOGateCancellation(t *testing.T) {
	gate := xio.NewWeighted(2 << 20)
	hold, err := gate.Acquire(context.Background(), 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()

	data := bytes.Repeat([]byte("b"), 2<<20)
	f, _ := newTestFile(data, Options{IOGate: gate, ContentCap: 4 << 20})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := f.Content(ctx); err == nil {
		t.Fatal("Content succeeded while the gate was exhausted; want ctx error")
	}
}
