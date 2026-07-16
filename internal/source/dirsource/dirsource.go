// Package dirsource implements the filesystem source (ARCHITECTURE.md §7):
// streaming enumeration with a nested per-directory .gitignore/.airomignore
// stack, non-overridable default skips, user --ignore globs, and an
// ignore-honoring resolver for the phase-2 pull API. Symlinks are never
// followed (which also forecloses cycles); non-regular files are skipped;
// permission failures below the root degrade to Unknown records (invariant
// P6) while an unreadable root is a fatal source-acquisition failure.
//
// Concurrency: Walk keeps all traversal state walk-local, so concurrent
// Walks — including the Resolver's pulls, which run in parallel during
// phase 2 (§8) — are safe.
package dirsource

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/charlievieth/fastwalk"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/source"
)

// defaultIgnoreLines are the always-on skips (docs/cli.md ".airomignore"):
// VCS and dependency internals. They are evaluated in an ISOLATED matcher
// consulted before the user's ignore stack, so no `!` re-inclusion rule can
// override them — "always-on" is enforced, not aspirational. All lines are
// lowercase, so the same matcher serves case-folding platforms.
var defaultIgnoreLines = []string{
	".git/",
	"node_modules/",
	"vendor/",
	".venv/",
	"venv/",
	"__pycache__/",
	".tox/",
	".mypy_cache/",
}

var defaultMatcher = func() gitignore.Matcher {
	patterns := make([]gitignore.Pattern, 0, len(defaultIgnoreLines))
	for _, line := range defaultIgnoreLines {
		patterns = append(patterns, gitignore.ParsePattern(line, nil))
	}
	return gitignore.NewMatcher(patterns)
}()

// ignoreFileNames are read per directory, in order — .airomignore is applied
// on top of .gitignore, so it can re-include (!) what .gitignore excluded.
var ignoreFileNames = []string{".gitignore", ".airomignore"}

// utf8BOM is stripped from the head of ignore files, matching git.
const utf8BOM = "\xef\xbb\xbf"

// Options configures a directory source.
type Options struct {
	// IgnoreGlobs are user --ignore doublestar patterns over root-relative
	// slash paths, applied on top of the ignore-file stack.
	IgnoreGlobs []string
}

// Source is the dir implementation of source.Source.
type Source struct {
	root         string // absolute, cleaned
	rootResolved string // symlink-resolved root, for resolver containment
	opts         Options

	// foldCase mirrors git's core.ignorecase default on platforms whose
	// filesystems are case-insensitive by default: ignore matching folds
	// case so AIROM skips what the user's git skips.
	foldCase bool

	mu       sync.Mutex
	unknowns []source.Unknown // published by the most recent Walk
}

type ignoreNode struct {
	patterns []gitignore.Pattern // ancestors + own, in order (defaults are separate)
	matcher  gitignore.Matcher   // last-match-wins over patterns
}

// New validates the target and prepares a directory source.
func New(root string, opts Options) (*Source, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", root, err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("cannot scan %q: %w", root, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("cannot scan %q: not a directory (single-file scanning is not supported; scan the containing directory)", root)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", root, err)
	}
	for _, g := range opts.IgnoreGlobs {
		if !doublestar.ValidatePattern(g) {
			return nil, fmt.Errorf("--ignore: invalid glob %q", g)
		}
	}
	return &Source{
		root:         abs,
		rootResolved: resolved,
		opts:         opts,
		foldCase:     runtime.GOOS == "darwin" || runtime.GOOS == "windows",
	}, nil
}

// Name returns the absolute scan root.
func (s *Source) Name() string { return s.root }

// Kind reports the source kind ("dir").
func (s *Source) Kind() source.Kind { return source.KindDir }

// ID is the cache-key identity of this source.
func (s *Source) ID() string { return "dir:" + s.root }

// Info returns the provenance root for the scan output.
func (s *Source) Info() source.Info { return source.Info{Kind: source.KindDir, Target: s.root} }

// Close is a no-op: dir sources hold no resources between walks.
func (s *Source) Close() error { return nil }

// WalkUnknowns returns walk-level failures published by the most recent
// top-level Walk. Resolver pulls never clobber these.
func (s *Source) WalkUnknowns() []source.Unknown {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]source.Unknown(nil), s.unknowns...)
}

// walkState is per-invocation traversal state: concurrent Walks (phase-2
// Resolver pulls run in parallel per §8) must never share or reset it.
type walkState struct {
	mu       sync.Mutex
	unknowns []source.Unknown

	// nodes maps root-relative dir path ("." for the root) to its ignore
	// state. Only directories that INTRODUCE patterns get an entry; lookup
	// walks to the nearest stored ancestor, so memory scales with ignore
	// files, not directory count (invariant P2). fastwalk guarantees a
	// directory's callback runs before its children's.
	nodes sync.Map
}

func (ws *walkState) record(path, stage string, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.unknowns = append(ws.unknowns, source.Unknown{Path: path, Stage: stage, Reason: err.Error()})
}

// lookup returns the ignore state governing rel's children: the node stored
// at rel or at its nearest stored ancestor ("." is always stored).
func (ws *walkState) lookup(rel string) *ignoreNode {
	for {
		if v, ok := ws.nodes.Load(rel); ok {
			return v.(*ignoreNode)
		}
		if rel == "." {
			// Unreachable: "." is stored before the walk starts. Return an
			// empty node rather than panicking a worker.
			return &ignoreNode{matcher: gitignore.NewMatcher(nil)}
		}
		if i := strings.LastIndexByte(rel, '/'); i >= 0 {
			rel = rel[:i]
		} else {
			rel = "."
		}
	}
}

// Walk streams regular, non-ignored files, then publishes the walk's
// Unknown records. Entries are emitted from multiple goroutines (fastwalk's
// internal parallelism); Walk returns only after every callback has
// returned, so a caller may close a channel after Walk without racing sends.
func (s *Source) Walk(ctx context.Context, fn source.WalkFunc) error {
	ws := &walkState{}
	err := s.walk(ctx, fn, ws)
	s.mu.Lock()
	s.unknowns = ws.unknowns
	s.mu.Unlock()
	return err
}

// walk runs one traversal against walk-local state.
func (s *Source) walk(ctx context.Context, fn source.WalkFunc, ws *walkState) error {
	ws.nodes.Store(".", s.rootNode())

	conf := fastwalk.Config{Follow: false}
	err := fastwalk.Walk(&conf, s.root, func(path string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			if path == s.root {
				// An unreadable scan root is a source-acquisition failure:
				// fatal per the docs/cli.md exit-code contract, never a
				// silent "0 files walked" success.
				return fmt.Errorf("cannot scan %q: %w", s.root, err)
			}
			ws.record(s.rel(path), "walk", err)
			return nil // below the root: degrade, never die (P6)
		}
		if path == s.root {
			return nil // root node pre-stored
		}

		rel := s.rel(path)
		segments := strings.Split(rel, "/")
		matchSegs := s.matchSegments(segments)
		parent := "."
		if i := strings.LastIndexByte(rel, '/'); i >= 0 {
			parent = rel[:i]
		}

		if d.IsDir() {
			if defaultMatcher.Match(matchSegs, true) {
				return fastwalk.SkipDir // non-overridable by design
			}
			node := ws.lookup(parent)
			if node.matcher.Match(matchSegs, true) || s.userIgnored(rel, true) {
				return fastwalk.SkipDir
			}
			if child := s.childNode(node, path, matchSegs); child != node {
				ws.nodes.Store(rel, child)
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil // symlinks, sockets, devices: never followed or read
		}
		if defaultMatcher.Match(matchSegs, false) {
			return nil
		}
		node := ws.lookup(parent)
		if node.matcher.Match(matchSegs, false) || s.userIgnored(rel, false) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			ws.record(rel, "stat", err)
			return nil
		}

		abs := path
		return fn(source.Entry{
			Ref: classify.FileRef{
				Path:     rel,
				Size:     info.Size(),
				Mode:     info.Mode(),
				ModTime:  info.ModTime(),
				Language: classify.LanguageOf(rel),
			},
			Open: func() (io.ReadCloser, error) { return os.Open(abs) }, // #nosec G304 -- scanning files under the walk root is the product
			ReaderAt: func() (source.ReaderAtCloser, error) {
				return os.Open(abs) // #nosec G304 -- same walk-root path; *os.File is ReaderAt+Closer, caller closes
			},
		})
	})
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// matchSegments returns the segments used for ignore matching: folded to
// lower case on platforms where git defaults core.ignorecase=true, so
// pattern semantics match the user's git.
func (s *Source) matchSegments(segments []string) []string {
	if !s.foldCase {
		return segments
	}
	folded := make([]string, len(segments))
	for i, seg := range segments {
		folded[i] = strings.ToLower(seg)
	}
	return folded
}

func (s *Source) rootNode() *ignoreNode {
	patterns := s.readIgnoreFiles(s.root, nil)
	return &ignoreNode{patterns: patterns, matcher: gitignore.NewMatcher(patterns)}
}

// childNode layers dir's own ignore files onto the parent's. domain is the
// (possibly case-folded) segment path of dir. Returns parent unchanged when
// the directory introduces no patterns — the node map stays proportional to
// ignore files, not directories.
func (s *Source) childNode(parent *ignoreNode, dirAbs string, domain []string) *ignoreNode {
	own := s.readIgnoreFiles(dirAbs, domain)
	if len(own) == 0 {
		return parent
	}
	// Full copy: appending to a shared backing array would race siblings.
	patterns := make([]gitignore.Pattern, 0, len(parent.patterns)+len(own))
	patterns = append(patterns, parent.patterns...)
	patterns = append(patterns, own...)
	return &ignoreNode{patterns: patterns, matcher: gitignore.NewMatcher(patterns)}
}

// readIgnoreFiles parses .gitignore then .airomignore in dir. domain scopes
// the patterns exactly as git does. Git parity details handled here: a
// leading UTF-8 BOM is stripped (file-level, like git's skip_utf8_bom);
// trailing-`/**` patterns are rewritten to `/**/*` because go-git's matcher
// would otherwise prune the base directory itself, breaking the standard
// `dir/**` + `!dir/keep` re-inclusion idiom (git descends and re-includes);
// case is folded on core.ignorecase platforms.
//
// Known limitation (documented in docs/cli.md): POSIX character classes
// ([[:digit:]]) are not supported by the underlying matcher.
func (s *Source) readIgnoreFiles(dir string, domain []string) []gitignore.Pattern {
	var patterns []gitignore.Pattern
	for _, name := range ignoreFileNames {
		data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- reads .gitignore/.airomignore under the walk root
		if err != nil {
			continue
		}
		content := strings.TrimPrefix(string(data), utf8BOM)
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimRight(line, "\r")
			if strings.HasPrefix(line, "#") || len(strings.TrimSpace(line)) == 0 {
				continue
			}
			if strings.HasSuffix(line, "/**") {
				line += "/*" // match all contents, not the directory itself
			}
			if s.foldCase {
				line = strings.ToLower(line)
			}
			patterns = append(patterns, gitignore.ParsePattern(line, domain))
		}
	}
	return patterns
}

func (s *Source) userIgnored(rel string, isDir bool) bool {
	if s.foldCase {
		rel = strings.ToLower(rel)
	}
	for _, g := range s.opts.IgnoreGlobs {
		if s.foldCase {
			g = strings.ToLower(g)
		}
		if ok, _ := doublestar.Match(g, rel); ok {
			return true
		}
		if isDir {
			// A glob like "**/fixtures/**" should also prune the fixtures
			// dir itself, not just its contents.
			if ok, _ := doublestar.Match(g, rel+"/"); ok {
				return true
			}
		}
	}
	return false
}

func (s *Source) rel(path string) string {
	rel, err := filepath.Rel(s.root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// ── Resolver: ignore-honoring pull API for phase-2 detectors ────────────────

// Resolver returns the pull-style query API. Every method honors the same
// ignore rules as Walk — a phase-2 detector can never see a file phase 1
// could not — and confines access to the scan root even through symlinks.
// Safe for concurrent use (walk state is per-invocation).
func (s *Source) Resolver() source.Resolver { return &resolver{s: s} }

type resolver struct{ s *Source }

func (r *resolver) FilesByGlob(ctx context.Context, patterns ...string) ([]classify.FileRef, error) {
	for _, p := range patterns {
		if !doublestar.ValidatePattern(p) {
			return nil, fmt.Errorf("invalid glob %q", p)
		}
	}
	var (
		mu  sync.Mutex
		out []classify.FileRef
	)
	// Private walkState: a resolver pull must never clobber the phase-1
	// WalkUnknowns nor race another pull.
	ws := &walkState{}
	err := r.s.walk(ctx, func(en source.Entry) error {
		for _, p := range patterns {
			if ok, _ := doublestar.Match(p, en.Ref.Path); ok {
				mu.Lock()
				out = append(out, en.Ref)
				mu.Unlock()
				return nil
			}
		}
		return nil
	}, ws)
	return out, err
}

// errIgnored marks paths the scan's ignore rules exclude.
var errIgnored = fmt.Errorf("path is excluded by the scan's ignore rules")

func (r *resolver) Open(rel string) (io.ReadCloser, error) {
	abs, err := r.abs(rel)
	if err != nil {
		return nil, err
	}
	if r.ignored(rel) {
		return nil, fmt.Errorf("open %q: %w", rel, errIgnored)
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("open %q: not a regular file (symlinks are never followed)", rel)
	}
	return os.Open(abs) // #nosec G304 -- abs() confines to the scan root incl. symlink resolution
}

func (r *resolver) Stat(rel string) (classify.FileRef, error) {
	abs, err := r.abs(rel)
	if err != nil {
		return classify.FileRef{}, err
	}
	if r.ignored(rel) {
		return classify.FileRef{}, fmt.Errorf("stat %q: %w", rel, errIgnored)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return classify.FileRef{}, err
	}
	if !info.Mode().IsRegular() {
		return classify.FileRef{}, fmt.Errorf("stat %q: not a regular file (symlinks are never followed)", rel)
	}
	return classify.FileRef{
		Path:     rel,
		Size:     info.Size(),
		Mode:     info.Mode(),
		ModTime:  info.ModTime(),
		Language: classify.LanguageOf(rel),
	}, nil
}

// ignored re-evaluates the full layered ignore rules (defaults, nested
// ignore files, user globs) for one path, exactly as Walk would.
func (r *resolver) ignored(rel string) bool {
	segs := strings.Split(rel, "/")
	matchSegs := r.s.matchSegments(segs)
	node := r.s.rootNode()
	dirAbs := r.s.root
	for i := range segs {
		isLeaf := i == len(segs)-1
		prefix := matchSegs[:i+1]
		relPath := strings.Join(segs[:i+1], "/")
		if defaultMatcher.Match(prefix, !isLeaf) ||
			node.matcher.Match(prefix, !isLeaf) ||
			r.s.userIgnored(relPath, !isLeaf) {
			return true
		}
		if !isLeaf {
			dirAbs = filepath.Join(dirAbs, segs[i])
			node = r.s.childNode(node, dirAbs, matchSegs[:i+1])
		}
	}
	return false
}

// abs resolves a root-relative path with two containment layers: lexical
// (no traversal) and physical (symlink resolution must stay under the
// resolved root) — resolver inputs may originate from scanned (untrusted)
// content.
func (r *resolver) abs(rel string) (string, error) {
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return "", fmt.Errorf("path %q escapes the scan root", rel)
	}
	abs := filepath.Join(r.s.root, filepath.FromSlash(rel))
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	if resolved != r.s.rootResolved &&
		!strings.HasPrefix(resolved, r.s.rootResolved+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the scan root via symlink", rel)
	}
	return abs, nil
}
