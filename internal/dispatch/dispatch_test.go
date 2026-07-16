package dispatch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/filectx"
	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// fakeFD is a scripted FileDetector.
type fakeFD struct {
	id  string
	sel detect.Selector
	fn  func(ctx context.Context, f *detect.File) ([]detect.Finding, error)
}

func (d *fakeFD) ID() string                { return d.id }
func (d *fakeFD) Version() int              { return 1 }
func (d *fakeFD) Selector() detect.Selector { return d.sel }
func (d *fakeFD) DetectFile(ctx context.Context, f *detect.File) ([]detect.Finding, error) {
	return d.fn(ctx, f)
}

// newTestFile builds a filectx.File over in-memory bytes with an
// open-counting provider.
func newTestFile(path string, data []byte) (*filectx.File, *int) {
	opens := 0
	ref := classify.FileRef{
		Path:     path,
		Size:     int64(len(data)),
		Language: classify.LanguageOf(path),
	}
	header := data
	if len(header) > filectx.HeaderSize {
		header = header[:filectx.HeaderSize]
	}
	f := filectx.New(ref, header, func() (io.ReadCloser, error) {
		opens++
		return io.NopCloser(bytes.NewReader(data)), nil
	}, filectx.Options{})
	return f, &opens
}

// TestPanicIsolationAndAttribution: one detector's panic becomes an
// attributed Unknown; the file's OTHER detectors still run (P6).
func TestPanicIsolationAndAttribution(t *testing.T) {
	boom := &fakeFD{id: "boom", fn: func(context.Context, *detect.File) ([]detect.Finding, error) {
		panic("detector bug")
	}}
	ok := &fakeFD{id: "ok", fn: func(_ context.Context, _ *detect.File) ([]detect.Finding, error) {
		return []detect.Finding{{
			Claim:      detect.ComponentClaim{Kind: airom.KindHostedLLM, Name: "m"},
			Occurrence: airom.Occurrence{Method: airom.MethodSourceCode, Confidence: 0.5},
		}}, nil
	}}
	d, err := New([]detect.FileDetector{boom, ok})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := newTestFile("a.py", []byte("x = 1\n"))
	payload, err := d.Process(context.Background(), f)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	res := payload.(*Result)
	if len(res.Findings) != 1 || res.Findings[0].Occurrence.DetectorID != "ok" {
		t.Errorf("findings = %+v, want the surviving detector's", res.Findings)
	}
	if len(res.Unknowns) != 1 || res.Unknowns[0].DetectorID != "boom" ||
		!strings.Contains(res.Unknowns[0].Reason, "panic: detector bug") {
		t.Errorf("unknowns = %+v, want attributed panic", res.Unknowns)
	}
}

// TestSnippetNeverForcesRead: a finding with Line>0 from a detector that
// never read content must NOT trigger a content read for the snippet (P3).
func TestSnippetNeverForcesRead(t *testing.T) {
	headerOnly := &fakeFD{id: "header-only", fn: func(_ context.Context, f *detect.File) ([]detect.Finding, error) {
		_ = f.Header() // header is pre-read; content never touched
		return []detect.Finding{{
			Claim:      detect.ComponentClaim{Kind: airom.KindDataset, Name: "d"},
			Occurrence: airom.Occurrence{Location: airom.Location{Line: 1}, Method: airom.MethodFilename, Confidence: 0.4},
		}}, nil
	}}
	d, err := New([]detect.FileDetector{headerOnly})
	if err != nil {
		t.Fatal(err)
	}
	f, opens := newTestFile("data.csv", []byte("a,b\n1,2\n"))
	payload, err := d.Process(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if *opens != 0 {
		t.Errorf("content opens = %d, want 0 (snippet fill must not force a read)", *opens)
	}
	res := payload.(*Result)
	if res.Findings[0].Occurrence.Snippet != "" {
		t.Errorf("snippet = %q, want empty when content was never loaded", res.Findings[0].Occurrence.Snippet)
	}
}

// TestSnippetFilledWhenLoaded: when a detector DID read content, the
// dispatcher fills missing snippets from the line.
func TestSnippetFilledWhenLoaded(t *testing.T) {
	reader := &fakeFD{id: "reader", fn: func(_ context.Context, f *detect.File) ([]detect.Finding, error) {
		if _, err := f.Content(); err != nil {
			return nil, err
		}
		return []detect.Finding{{
			Claim:      detect.ComponentClaim{Kind: airom.KindHostedLLM, Name: "gpt-4.1"},
			Occurrence: airom.Occurrence{Location: airom.Location{Line: 2}, Method: airom.MethodSourceCode, Confidence: 0.8},
		}}, nil
	}}
	d, err := New([]detect.FileDetector{reader})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := newTestFile("a.py", []byte("import openai\nmodel = \"gpt-4.1\"\n"))
	payload, err := d.Process(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	res := payload.(*Result)
	if got := res.Findings[0].Occurrence.Snippet; got != `model = "gpt-4.1"` {
		t.Errorf("snippet = %q", got)
	}
}

// TestWeightsAutoHash: local-model-file claims get the tee-hash for free
// when the content was fully read.
func TestWeightsAutoHash(t *testing.T) {
	w := &fakeFD{id: "weights", fn: func(_ context.Context, f *detect.File) ([]detect.Finding, error) {
		if _, err := f.Content(); err != nil {
			return nil, err
		}
		return []detect.Finding{{
			Claim:      detect.ComponentClaim{Kind: airom.KindLocalModelFile, Name: "m.gguf"},
			Occurrence: airom.Occurrence{Method: airom.MethodBinary, Confidence: 0.9},
		}}, nil
	}}
	d, err := New([]detect.FileDetector{w})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := newTestFile("m.gguf", append([]byte("GGUF"), 1, 2, 3))
	payload, err := d.Process(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	res := payload.(*Result)
	if len(res.Findings[0].Claim.Hashes) != 1 || res.Findings[0].Claim.Hashes[0].Alg != "SHA-256" {
		t.Errorf("hashes = %+v, want the free SHA-256", res.Findings[0].Claim.Hashes)
	}
}

// fakePD is a scripted ProjectDetector.
type fakePD struct {
	id string
	fn func(ctx context.Context) ([]detect.Finding, error)
}

func (d *fakePD) ID() string                { return d.id }
func (d *fakePD) Version() int              { return 1 }
func (d *fakePD) Selector() detect.Selector { return detect.Selector{} }
func (d *fakePD) DetectProject(ctx context.Context, _ detect.Resolver, _ *detect.FindingsView) ([]detect.Finding, error) {
	return d.fn(ctx)
}

// TestRunProjectCancellationAborts: Ctrl-C during phase 2 must surface as
// an error, never as a "successful" truncated scan.
func TestRunProjectCancellationAborts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hang := &fakePD{id: "hang", fn: func(c context.Context) ([]detect.Finding, error) {
		<-c.Done()
		return nil, c.Err()
	}}
	done := make(chan error, 1)
	go func() {
		_, err := RunProject(ctx, []detect.ProjectDetector{hang}, nil, detect.NewFindingsView(nil), 2)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation swallowed: RunProject returned nil error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunProject hung after cancel")
	}
}

// TestRunProjectDegradesFailuresAndAccounts: detector errors degrade to
// attributed Unknowns; per-detector stats cover phase 2.
func TestRunProjectDegradesFailuresAndAccounts(t *testing.T) {
	bad := &fakePD{id: "bad", fn: func(context.Context) ([]detect.Finding, error) {
		return nil, errors.New("cross-file confusion")
	}}
	good := &fakePD{id: "good", fn: func(context.Context) ([]detect.Finding, error) {
		return []detect.Finding{{
			Claim:      detect.ComponentClaim{Kind: airom.KindRAGPipeline, Name: "rag"},
			Occurrence: airom.Occurrence{Method: airom.MethodSourceCode, Confidence: 0.6},
		}}, nil
	}}
	out, err := RunProject(context.Background(), []detect.ProjectDetector{bad, good}, nil, detect.NewFindingsView(nil), 2)
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if len(out.Findings) != 1 || out.Findings[0].Occurrence.DetectorID != "good" {
		t.Errorf("findings = %+v", out.Findings)
	}
	if len(out.Unknowns) != 1 || out.Unknowns[0].DetectorID != "bad" {
		t.Errorf("unknowns = %+v", out.Unknowns)
	}
	if len(out.Stats) != 2 || out.Stats[0].ID != "bad" || out.Stats[1].ID != "good" {
		t.Errorf("stats = %+v, want sorted per-detector accounting", out.Stats)
	}
	if out.Stats[1].Findings != 1 || out.Stats[1].Invocations != 1 {
		t.Errorf("good stats = %+v", out.Stats[1])
	}
}

// TestAdaptFileSeekabilityMapping: filectx's ErrNotSeekable maps to the
// public detect.ErrNotSeekable.
func TestAdaptFileSeekabilityMapping(t *testing.T) {
	f, _ := newTestFile("x.py", []byte("data"))
	df := adaptFile(context.Background(), f, toDetectRef(f.Ref))
	if _, err := df.ReaderAt(); !errors.Is(err, detect.ErrNotSeekable) {
		t.Errorf("err = %v, want detect.ErrNotSeekable", err)
	}
}
