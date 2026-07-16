// Package engine implements the phase-1 streaming scan pipeline
// (ARCHITECTURE.md §8): exactly one producer walking the source into a
// bounded task channel, a file-worker pool running the processor on
// read-once file contexts, and exactly one collector goroutine owning all
// aggregation state. Backpressure is structural (bounded channels), memory
// is bounded by configuration (invariant P2), detector errors and panics
// degrade to Unknowns (invariant P6), and output is deterministic at any
// parallelism (invariant P7; the collector sorts before returning).
//
// The processor seam is where the Phase-5 dispatcher plugs in; the engine
// itself knows nothing about detectors.
package engine

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/filectx"
	"github.com/Roro1727/airom/internal/source"
	"github.com/Roro1727/airom/internal/xio"
)

// Processor runs all interested consumers for one file (the Phase-5
// dispatcher). The returned payload flows to the collector; an error (or
// panic) degrades to an Unknown record for that file. A nil Processor
// yields a classification-only scan.
type Processor interface {
	Process(ctx context.Context, f *filectx.File) (payload any, err error)
}

// Options bound the pipeline (P2). Zero values take documented defaults.
type Options struct {
	Parallel    int   // workers; default GOMAXPROCS
	IOBudget    int64 // byte-weighted I/O semaphore budget; default 256 MiB
	MaxFileSize int64 // full-content read cap; default 1 MiB
}

// Payload is one file's processor output, ordered by path in the Outcome.
type Payload struct {
	Path  string
	Value any
}

// Stats are the pipeline's own counters (a ScanStats ingredient, §14).
type Stats struct {
	FilesWalked    int64 // entries emitted by the source (post-ignore)
	FilesProcessed int64 // files a processor ran on without error
	FilesFailed    int64 // files degraded to Unknowns
	HeaderBytes    int64 // bytes read into header samples
	ContentBytes   int64 // bytes read as bounded content
	// Duration is legitimately nondeterministic; the Phase-7 writers must
	// exclude or normalize it to preserve the P7 byte-identical contract.
	Duration time.Duration
}

// Outcome is the aggregated result of one phase-1 scan.
type Outcome struct {
	Payloads []Payload
	Unknowns []source.Unknown
	Stats    Stats
}

// Engine executes phase-1 scans. Safe for reuse across scans, not for
// concurrent scans.
type Engine struct {
	opts        Options
	ioGate      *xio.Weighted
	headerPool  *xio.BufPool
	contentPool *xio.BufPool
}

// contentPoolClass caps the pooled content-buffer size: MaxFileSize is user
// tunable and pooling multi-hundred-MiB buffers would pin memory; larger
// reads simply allocate.
const contentPoolClass = 1 << 20

// New builds an engine with defaulted options.
func New(opts Options) *Engine {
	if opts.Parallel <= 0 {
		opts.Parallel = runtime.GOMAXPROCS(0)
	}
	if opts.IOBudget == 0 {
		opts.IOBudget = 256 << 20
	}
	if opts.MaxFileSize == 0 {
		opts.MaxFileSize = 1 << 20
	}
	poolSize := contentPoolClass
	if opts.MaxFileSize < int64(poolSize) {
		poolSize = int(opts.MaxFileSize)
	}
	return &Engine{
		opts:        opts,
		ioGate:      xio.NewWeighted(opts.IOBudget),
		headerPool:  xio.NewBufPool(filectx.HeaderSize),
		contentPool: xio.NewBufPool(poolSize),
	}
}

type result struct {
	path         string
	payload      any
	unknowns     []source.Unknown
	headerBytes  int64
	contentBytes int64
	processed    bool
}

// Scan runs the phase-1 pipeline over src. The returned error is reserved
// for cancellation and catastrophic failure; per-file trouble is in
// Outcome.Unknowns (P6).
func (e *Engine) Scan(ctx context.Context, src source.Source, proc Processor) (*Outcome, error) {
	start := time.Now()
	g, ctx := errgroup.WithContext(ctx)

	workers := e.opts.Parallel
	tasks := make(chan source.Entry, 4*workers)
	results := make(chan result, 256)

	var walked atomic.Int64

	// 1) Exactly one producer owns and closes tasks. The source's Walk may
	//    fan out internally (fastwalk); sends on tasks are safe from many
	//    goroutines, and Walk returns only after every callback has, so the
	//    deferred close cannot race a send.
	g.Go(func() error {
		defer close(tasks)
		return src.Walk(ctx, func(en source.Entry) error {
			select {
			case tasks <- en:
				walked.Add(1)
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})

	// 2) Worker pool: all consumers for one file run sequentially in one
	//    worker on one shared, read-once buffer — parallelism is across
	//    files, never per (file, detector).
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		g.Go(func() error {
			defer wg.Done()
			for en := range tasks {
				res := e.processEntry(ctx, en, proc)
				select {
				case results <- res:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}
	// Close results only after ALL workers exit.
	go func() { wg.Wait(); close(results) }()

	// 3) Exactly one collector goroutine owns all mutable aggregation
	//    state. No locks anywhere in the aggregation path.
	out := &Outcome{}
	g.Go(func() error {
		for r := range results {
			if r.payload != nil {
				out.Payloads = append(out.Payloads, Payload{Path: r.path, Value: r.payload})
			}
			out.Unknowns = append(out.Unknowns, r.unknowns...)
			out.Stats.HeaderBytes += r.headerBytes
			out.Stats.ContentBytes += r.contentBytes
			if r.processed {
				out.Stats.FilesProcessed++
			}
			if len(r.unknowns) > 0 {
				out.Stats.FilesFailed++
			}
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	out.Unknowns = append(out.Unknowns, src.WalkUnknowns()...)
	out.Stats.FilesWalked = walked.Load()
	out.Stats.Duration = time.Since(start)

	// Determinism (P7): concurrency never leaks into output ordering.
	sort.Slice(out.Payloads, func(i, j int) bool { return out.Payloads[i].Path < out.Payloads[j].Path })
	sort.Slice(out.Unknowns, func(i, j int) bool {
		a, b := out.Unknowns[i], out.Unknowns[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Stage != b.Stage {
			return a.Stage < b.Stage
		}
		return a.Reason < b.Reason
	})
	return out, nil
}

// processEntry reads the header sample, completes classification, runs the
// processor, and degrades every failure — including panics — to Unknowns.
func (e *Engine) processEntry(ctx context.Context, en source.Entry, proc Processor) (res result) {
	res.path = en.Ref.Path

	defer func() {
		if p := recover(); p != nil {
			stack := debug.Stack()
			if len(stack) > 2048 {
				stack = stack[:2048]
			}
			res.unknowns = append(res.unknowns, source.Unknown{
				Path:   en.Ref.Path,
				Stage:  "process",
				Reason: fmt.Sprintf("panic: %v\n%s", p, stack),
			})
		}
	}()

	// Header sample: one bounded read shared by binary sniff, magic match,
	// and every header-interested consumer.
	headerBuf := e.headerPool.Get()
	defer e.headerPool.Put(headerBuf)

	header, err := readHeader(en, headerBuf)
	if err != nil {
		res.unknowns = append(res.unknowns, source.Unknown{Path: en.Ref.Path, Stage: "header", Reason: err.Error()})
		return res
	}
	res.headerBytes = int64(len(header))

	ref := en.Ref
	ref.Binary = classify.IsBinary(header)
	ref.MagicID = classify.MatchMagic(header)

	var raFn func() (filectx.ReaderAtCloser, error)
	if en.ReaderAt != nil {
		ra := en.ReaderAt
		raFn = func() (filectx.ReaderAtCloser, error) { return ra() }
	}

	f := filectx.New(ref, header, en.Open, filectx.Options{
		ContentCap: e.opts.MaxFileSize,
		IOGate:     e.ioGate,
		Pool:       e.contentPool,
		ReaderAt:   raFn,
	})
	defer f.Release()
	// Deferred so byte accounting survives the panic-recovery path too:
	// bytes were read from the source whether or not the processor lived.
	defer func() { res.contentBytes = f.BytesRead() }()

	if proc == nil {
		res.processed = true
		return res
	}

	payload, err := proc.Process(ctx, f)
	if err != nil {
		res.unknowns = append(res.unknowns, source.Unknown{Path: en.Ref.Path, Stage: "process", Reason: err.Error()})
		return res
	}
	res.payload = payload
	res.processed = true
	return res
}

// readHeader fills buf with up to HeaderSize bytes from the entry.
func readHeader(en source.Entry, buf []byte) ([]byte, error) {
	rc, err := en.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	want := int64(len(buf))
	if en.Ref.Size >= 0 && en.Ref.Size < want {
		want = en.Ref.Size
	}
	n, err := io.ReadFull(rc, buf[:want])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:n], nil
}
