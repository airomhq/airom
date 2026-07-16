// Package dispatch routes classified files to interested detectors through
// the compiled selector index (ARCHITECTURE.md §6.1) and adapts the
// internal read-once file context to the public SDK's detect.File. It is
// the engine's Processor: all matched detectors run sequentially per file
// on the one shared buffer (§8), each isolated so one detector's failure
// degrades to an attributed Unknown — never the file, never the scan (P6).
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/filectx"
	"github.com/Roro1727/airom/internal/source"
	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Result is the per-file (phase 1) or per-scan (phase 2) payload flowing to
// the collector: findings plus per-detector attributed unknowns.
type Result struct {
	Findings []detect.Finding
	Unknowns []airom.Unknown
}

// detectorCounters accumulate per-detector runtime accounting (--stats).
type detectorCounters struct {
	invocations atomic.Int64
	findings    atomic.Int64
	ns          atomic.Int64
}

// Dispatcher implements engine.Processor over the compiled index.
type Dispatcher struct {
	index    *detect.Index
	counters map[string]*detectorCounters // fixed at construction; values are atomic
}

// New compiles the selector index over the selected file detectors.
func New(fileDetectors []detect.FileDetector) (*Dispatcher, error) {
	ds := make([]detect.Detector, len(fileDetectors))
	counters := make(map[string]*detectorCounters, len(fileDetectors))
	for i, d := range fileDetectors {
		ds[i] = d
		counters[d.ID()] = &detectorCounters{}
	}
	ix, err := detect.NewIndex(ds)
	if err != nil {
		return nil, fmt.Errorf("compile selector index: %w", err)
	}
	return &Dispatcher{index: ix, counters: counters}, nil
}

// Process runs every matched detector for one file, sequentially, on the
// shared read-once context. Returns a *Result payload (nil when nothing
// matched and nothing failed).
func (d *Dispatcher) Process(ctx context.Context, f *filectx.File) (any, error) {
	ref := toDetectRef(f.Ref)
	matched := d.index.Match(ref, f.Header())
	if len(matched) == 0 {
		return nil, nil
	}

	df := adaptFile(ctx, f, ref)
	res := &Result{}
	for _, det := range matched {
		fd := det.(detect.FileDetector) // Dispatcher is built from FileDetectors only
		findings, err := d.runOne(ctx, fd, df)
		if err != nil {
			res.Unknowns = append(res.Unknowns, airom.Unknown{
				Path:       ref.Path,
				DetectorID: fd.ID(),
				Reason:     err.Error(),
			})
			continue
		}
		for i := range findings {
			d.finishFinding(&findings[i], fd, f, ref)
		}
		res.Findings = append(res.Findings, findings...)
	}

	if len(res.Findings) == 0 && len(res.Unknowns) == 0 {
		return nil, nil
	}
	return res, nil
}

// runOne executes one detector with panic isolation and accounting.
func (d *Dispatcher) runOne(ctx context.Context, fd detect.FileDetector, df *detect.File) (findings []detect.Finding, err error) {
	c := d.counters[fd.ID()]
	c.invocations.Add(1)
	start := time.Now()
	defer func() {
		c.ns.Add(time.Since(start).Nanoseconds())
		if p := recover(); p != nil {
			stack := debug.Stack()
			if len(stack) > 2048 {
				stack = stack[:2048]
			}
			findings = nil
			err = fmt.Errorf("panic: %v\n%s", p, stack)
		}
	}()

	findings, err = fd.DetectFile(ctx, df)
	if err == nil {
		c.findings.Add(int64(len(findings)))
	}
	return findings, err
}

// finishFinding applies the engine-owned conveniences (plugin-guide.md
// "Things the engine does FOR you"): detector attribution, location path,
// snippet capture, and the free content hash for weights files.
func (d *Dispatcher) finishFinding(f *detect.Finding, fd detect.FileDetector, fc *filectx.File, ref detect.FileRef) {
	if f.Occurrence.DetectorID == "" {
		f.Occurrence.DetectorID = fd.ID()
	}
	if f.Occurrence.Location.Path == "" {
		f.Occurrence.Location.Path = ref.Path
	}
	if f.Occurrence.Snippet == "" && f.Occurrence.Location.Line > 0 {
		if content, ok := fc.ContentIfLoaded(); ok {
			f.Occurrence.Snippet = lineSnippet(content, f.Occurrence.Location.Line)
		}
	}
	// Content-hash identity for weights files (§9.1) comes free from the
	// tee-hashed read — but only when the hash covers the WHOLE file.
	if f.Claim.Kind == airom.KindLocalModelFile && !hasSHA256(f.Claim.Hashes) {
		if sum, ok := fc.SHA256(); ok {
			f.Claim.Hashes = append(f.Claim.Hashes, airom.Hash{Alg: "SHA-256", Hex: fmt.Sprintf("%x", sum)})
		}
	}
}

func hasSHA256(hashes []airom.Hash) bool {
	for _, h := range hashes {
		if strings.EqualFold(h.Alg, "SHA-256") {
			return true
		}
	}
	return false
}

// lineSnippet extracts one 1-based line, sanitized and capped at 200 bytes
// (the occurrence snippet contract, §5).
func lineSnippet(content []byte, line int) string {
	start := 0
	for n := 1; n < line; n++ {
		i := indexByteFrom(content, start, '\n')
		if i < 0 {
			return ""
		}
		start = i + 1
	}
	end := indexByteFrom(content, start, '\n')
	if end < 0 {
		end = len(content)
	}
	return sanitizeSnippet(content[start:end])
}

func indexByteFrom(b []byte, from int, c byte) int {
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func sanitizeSnippet(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == '\t' {
			out = append(out, ' ')
			continue
		}
		if c < 0x20 || c == 0x7f {
			continue
		}
		out = append(out, c)
	}
	return strings.TrimSpace(string(out))
}

// Stats snapshots per-detector accounting for ScanStats, sorted by ID.
func (d *Dispatcher) Stats() []airom.DetectorStat {
	out := make([]airom.DetectorStat, 0, len(d.counters))
	for id, c := range d.counters {
		out = append(out, airom.DetectorStat{
			ID:          id,
			Invocations: c.invocations.Load(),
			Findings:    c.findings.Load(),
			NS:          c.ns.Load(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ── Phase 2: project detectors (§8) ────────────────────────────────────────

// ProjectOutcome is phase 2's aggregate: findings, attributed unknowns, and
// per-detector runtime accounting (the §14 "--stats" contract covers BOTH
// phases).
type ProjectOutcome struct {
	Result
	Stats []airom.DetectorStat
}

// RunProject executes the flat project-detector set on a bounded pool, each
// with the pull Resolver and the immutable phase-1 findings view. Detector
// failures degrade to attributed Unknowns (P6) — but CANCELLATION is not a
// detector failure: a canceled context aborts the phase with an error, so
// Ctrl-C can never masquerade as a successful (truncated) scan.
func RunProject(ctx context.Context, dets []detect.ProjectDetector, r detect.Resolver, prior *detect.FindingsView, workers int) (ProjectOutcome, error) {
	if len(dets) == 0 {
		return ProjectOutcome{}, nil
	}
	if workers <= 0 {
		workers = 1
	}

	type slot struct {
		findings []detect.Finding
		unknown  *airom.Unknown
		stat     airom.DetectorStat
	}
	slots := make([]slot, len(dets))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)
	for i, det := range dets {
		g.Go(func() error {
			start := time.Now()
			findings, err := runProjectOne(ctx, det, r, prior)
			slots[i].stat = airom.DetectorStat{
				ID:          det.ID(),
				Invocations: 1,
				Findings:    int64(len(findings)),
				NS:          time.Since(start).Nanoseconds(),
			}
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err // abort the phase (§8), don't degrade
				}
				slots[i].unknown = &airom.Unknown{
					Path:       ".",
					DetectorID: det.ID(),
					Reason:     err.Error(),
				}
				return nil // detector failure: degrade, never die
			}
			slots[i].findings = findings
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return ProjectOutcome{}, err
	}

	var out ProjectOutcome
	for i := range slots { // detector registration order = deterministic
		out.Findings = append(out.Findings, slots[i].findings...)
		if slots[i].unknown != nil {
			out.Unknowns = append(out.Unknowns, *slots[i].unknown)
		}
		out.Stats = append(out.Stats, slots[i].stat)
	}
	sort.Slice(out.Stats, func(i, j int) bool { return out.Stats[i].ID < out.Stats[j].ID })
	return out, nil
}

func runProjectOne(ctx context.Context, det detect.ProjectDetector, r detect.Resolver, prior *detect.FindingsView) (findings []detect.Finding, err error) {
	defer func() {
		if p := recover(); p != nil {
			stack := debug.Stack()
			if len(stack) > 2048 {
				stack = stack[:2048]
			}
			findings = nil
			err = fmt.Errorf("panic: %v\n%s", p, stack)
		}
	}()
	findings, err = det.DetectProject(ctx, r, prior)
	for i := range findings {
		if findings[i].Occurrence.DetectorID == "" {
			findings[i].Occurrence.DetectorID = det.ID()
		}
	}
	return findings, err
}

// ── Adapters: internal pipeline types → public SDK types ───────────────────

func toDetectRef(ref classify.FileRef) detect.FileRef {
	return detect.FileRef{
		Path:     ref.Path,
		Size:     ref.Size,
		Mode:     ref.Mode,
		ModTime:  ref.ModTime,
		Language: detect.Language(ref.Language),
		Binary:   ref.Binary,
		MagicID:  ref.MagicID,
	}
}

func adaptFile(ctx context.Context, f *filectx.File, ref detect.FileRef) *detect.File {
	return detect.NewFile(ref, f.Header(), detect.FileProviders{
		Content: func() ([]byte, bool, error) {
			return f.Content(ctx)
		},
		ReaderAt: func() (detect.ReaderAtCloser, error) {
			ra, err := f.ReaderAt()
			if err != nil {
				if errors.Is(err, filectx.ErrNotSeekable) {
					return nil, detect.ErrNotSeekable
				}
				return nil, err
			}
			return ra, nil
		},
		SHA256: f.SHA256,
		XXH3:   f.XXH3,
	})
}

// ResolverAdapter exposes an internal source.Resolver as the public
// detect.Resolver.
type ResolverAdapter struct {
	R source.Resolver
}

var _ detect.Resolver = ResolverAdapter{}

// FilesByGlob implements detect.Resolver.
func (a ResolverAdapter) FilesByGlob(ctx context.Context, patterns ...string) ([]detect.FileRef, error) {
	refs, err := a.R.FilesByGlob(ctx, patterns...)
	if err != nil {
		return nil, err
	}
	out := make([]detect.FileRef, len(refs))
	for i, r := range refs {
		out[i] = toDetectRef(r)
	}
	return out, nil
}

// Open implements detect.Resolver.
func (a ResolverAdapter) Open(path string) (io.ReadCloser, error) {
	return a.R.Open(path)
}

// Stat implements detect.Resolver.
func (a ResolverAdapter) Stat(path string) (detect.FileRef, error) {
	ref, err := a.R.Stat(path)
	if err != nil {
		return detect.FileRef{}, err
	}
	return toDetectRef(ref), nil
}
