package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/filectx"
	"github.com/Roro1727/airom/internal/source"
)

// memSource is an in-memory source.Source for controlled pipeline tests.
type memSource struct {
	files    map[string][]byte
	unknowns []source.Unknown
}

func (m *memSource) Name() string                   { return "mem" }
func (m *memSource) Kind() source.Kind              { return source.KindDir }
func (m *memSource) ID() string                     { return "mem:test" }
func (m *memSource) Info() source.Info              { return source.Info{Kind: source.KindDir, Target: "mem"} }
func (m *memSource) Close() error                   { return nil }
func (m *memSource) Resolver() source.Resolver      { return nil }
func (m *memSource) WalkUnknowns() []source.Unknown { return m.unknowns }

func (m *memSource) Walk(ctx context.Context, fn source.WalkFunc) error {
	for path, data := range m.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn(source.Entry{
			Ref: classify.FileRef{
				Path:     path,
				Size:     int64(len(data)),
				Language: classify.LanguageOf(path),
			},
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

type procFunc func(ctx context.Context, f *filectx.File) (any, error)

func (p procFunc) Process(ctx context.Context, f *filectx.File) (any, error) { return p(ctx, f) }

func testFiles(n int) map[string][]byte {
	files := map[string][]byte{}
	for i := 0; i < n; i++ {
		files[fmt.Sprintf("dir%d/file%d.py", i%7, i)] = []byte(fmt.Sprintf("content-%d", i))
	}
	return files
}

// TestDeterminism is invariant P7 at the pipeline level: identical inputs
// produce identical outcomes at any parallelism.
func TestDeterminism(t *testing.T) {
	src := &memSource{files: testFiles(200)}
	proc := procFunc(func(ctx context.Context, f *filectx.File) (any, error) {
		content, _, err := f.Content(ctx)
		if err != nil {
			return nil, err
		}
		return fmt.Sprintf("%s:%d", f.Ref.Path, len(content)), nil
	})

	run := func(parallel int) *Outcome {
		out, err := New(Options{Parallel: parallel}).Scan(context.Background(), src, proc)
		if err != nil {
			t.Fatalf("Scan(parallel=%d): %v", parallel, err)
		}
		out.Stats.Duration = 0 // timing is legitimately nondeterministic
		return out
	}

	one, sixteen := run(1), run(16)
	if !reflect.DeepEqual(one.Payloads, sixteen.Payloads) {
		t.Error("payloads differ between --parallel 1 and 16")
	}
	if !reflect.DeepEqual(one.Unknowns, sixteen.Unknowns) {
		t.Error("unknowns differ between --parallel 1 and 16")
	}
	if !reflect.DeepEqual(one.Stats, sixteen.Stats) {
		t.Errorf("stats differ:\n 1:  %+v\n 16: %+v", one.Stats, sixteen.Stats)
	}
	if one.Stats.FilesWalked != 200 || one.Stats.FilesProcessed != 200 {
		t.Errorf("stats = %+v", one.Stats)
	}
}

// TestPanicDegradesToUnknown is invariant P6: one exploding detector must
// never kill the scan, and the failure must be visible in the output.
func TestPanicDegradesToUnknown(t *testing.T) {
	src := &memSource{files: testFiles(20)}
	proc := procFunc(func(_ context.Context, f *filectx.File) (any, error) {
		if strings.HasSuffix(f.Ref.Path, "file7.py") {
			panic("detector bug")
		}
		return f.Ref.Path, nil
	})

	out, err := New(Options{Parallel: 4}).Scan(context.Background(), src, proc)
	if err != nil {
		t.Fatalf("Scan: %v (a panic must not fail the scan)", err)
	}
	if len(out.Payloads) != 19 {
		t.Errorf("payloads = %d, want 19", len(out.Payloads))
	}
	if len(out.Unknowns) != 1 || !strings.Contains(out.Unknowns[0].Reason, "panic: detector bug") {
		t.Errorf("unknowns = %+v, want one panic record", out.Unknowns)
	}
	if out.Stats.FilesFailed != 1 {
		t.Errorf("FilesFailed = %d, want 1", out.Stats.FilesFailed)
	}
}

func TestProcessorErrorDegrades(t *testing.T) {
	src := &memSource{files: map[string][]byte{"a.py": []byte("x"), "b.py": []byte("y")}}
	proc := procFunc(func(_ context.Context, f *filectx.File) (any, error) {
		if f.Ref.Path == "a.py" {
			return nil, errors.New("corrupt header")
		}
		return "ok", nil
	})
	out, err := New(Options{}).Scan(context.Background(), src, proc)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Unknowns) != 1 || out.Unknowns[0].Path != "a.py" {
		t.Errorf("unknowns = %+v", out.Unknowns)
	}
	if len(out.Payloads) != 1 || out.Payloads[0].Path != "b.py" {
		t.Errorf("payloads = %+v", out.Payloads)
	}
}

func TestClassificationFilledFromHeader(t *testing.T) {
	gguf := append([]byte("GGUF"), bytes.Repeat([]byte{0}, 100)...)
	src := &memSource{files: map[string][]byte{
		"models/llm.gguf": gguf,
		"app.py":          []byte("import openai\n"),
	}}
	var seen []string
	proc := procFunc(func(_ context.Context, f *filectx.File) (any, error) {
		seen = append(seen, fmt.Sprintf("%s magic=%s binary=%v", f.Ref.Path, f.Ref.MagicID, f.Ref.Binary))
		return nil, nil
	})
	if _, err := New(Options{Parallel: 1}).Scan(context.Background(), src, proc); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(seen, "\n")
	if !strings.Contains(joined, "models/llm.gguf magic=gguf binary=true") {
		t.Errorf("gguf not classified: %s", joined)
	}
	if !strings.Contains(joined, "app.py magic= binary=false") {
		t.Errorf("python misclassified: %s", joined)
	}
}

func TestCancellationStopsScan(t *testing.T) {
	src := &memSource{files: testFiles(500)}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var once sync.Once
	proc := procFunc(func(pctx context.Context, _ *filectx.File) (any, error) {
		once.Do(func() { close(started) })
		<-pctx.Done() // simulate a hung detector honoring ctx
		return nil, pctx.Err()
	})

	done := make(chan error, 1)
	go func() {
		_, err := New(Options{Parallel: 2}).Scan(ctx, src, proc)
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("want cancellation error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not stop after cancel")
	}
}

func TestWalkUnknownsMerged(t *testing.T) {
	src := &memSource{
		files:    map[string][]byte{"a.py": []byte("x")},
		unknowns: []source.Unknown{{Path: "locked", Stage: "walk", Reason: "permission denied"}},
	}
	out, err := New(Options{}).Scan(context.Background(), src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Unknowns) != 1 || out.Unknowns[0].Path != "locked" {
		t.Errorf("walk unknowns not merged: %+v", out.Unknowns)
	}
}

func TestNilProcessorClassifiesOnly(t *testing.T) {
	src := &memSource{files: testFiles(10)}
	out, err := New(Options{}).Scan(context.Background(), src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Payloads) != 0 {
		t.Errorf("payloads = %d, want 0", len(out.Payloads))
	}
	if out.Stats.FilesWalked != 10 || out.Stats.FilesProcessed != 10 {
		t.Errorf("stats = %+v", out.Stats)
	}
	if out.Stats.ContentBytes != 0 {
		t.Errorf("ContentBytes = %d, want 0 (no processor requested content)", out.Stats.ContentBytes)
	}
	if out.Stats.HeaderBytes == 0 {
		t.Error("HeaderBytes = 0, want header samples counted")
	}
}

// TestContentBytesCountedOnPanic: byte accounting must survive the
// panic-recovery path — the bytes were read either way.
func TestContentBytesCountedOnPanic(t *testing.T) {
	src := &memSource{files: map[string][]byte{"boom.py": bytes.Repeat([]byte("x"), 5000)}}
	proc := procFunc(func(ctx context.Context, f *filectx.File) (any, error) {
		if _, _, err := f.Content(ctx); err != nil {
			return nil, err
		}
		panic("after read")
	})
	out, err := New(Options{Parallel: 1}).Scan(context.Background(), src, proc)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stats.ContentBytes != 5000 {
		t.Errorf("ContentBytes = %d, want 5000 despite the panic", out.Stats.ContentBytes)
	}
}
