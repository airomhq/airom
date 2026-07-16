package xio

import (
	"context"
	"testing"
	"time"
)

// TestWeightedClamp is the 40GB-file-vs-256MiB-budget deadlock regression
// (ARCHITECTURE.md §8): a request larger than the budget must acquire the
// whole budget and proceed, never block forever.
func TestWeightedClamp(t *testing.T) {
	w := NewWeighted(256 << 20)

	done := make(chan struct{})
	go func() {
		defer close(done)
		release, err := w.Acquire(context.Background(), 40<<30) // 40 GiB
		if err != nil {
			t.Errorf("Acquire: %v", err)
			return
		}
		release()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("clamped Acquire deadlocked")
	}
}

func TestWeightedBlocksAndReleases(t *testing.T) {
	w := NewWeighted(100)

	rel1, err := w.Acquire(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}

	acquired := make(chan struct{})
	go func() {
		rel2, err := w.Acquire(context.Background(), 50)
		if err == nil {
			rel2()
		}
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("second Acquire succeeded while budget exhausted")
	case <-time.After(50 * time.Millisecond):
	}

	rel1()
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("second Acquire never unblocked after release")
	}

	rel1() // idempotent: double release must not over-credit
	rel3, err := w.Acquire(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	rel3()
}

func TestWeightedContextCancel(t *testing.T) {
	w := NewWeighted(10)
	rel, _ := w.Acquire(context.Background(), 10)
	defer rel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := w.Acquire(ctx, 5); err == nil {
		t.Fatal("want context error on exhausted budget")
	}
}

func TestWeightedUnlimited(t *testing.T) {
	w := NewWeighted(0)
	rel, err := w.Acquire(context.Background(), 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	rel()
}

func TestBufPool(t *testing.T) {
	p := NewBufPool(1024)
	b := p.Get()
	if len(b) != 1024 {
		t.Fatalf("len = %d, want 1024", len(b))
	}
	p.Put(b)
	p.Put(make([]byte, 10)) // wrong class: dropped, not poisoned
	b2 := p.Get()
	if len(b2) != 1024 {
		t.Fatalf("after foreign Put: len = %d, want 1024", len(b2))
	}
}
