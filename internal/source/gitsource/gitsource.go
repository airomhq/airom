package gitsource

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Roro1727/airom/internal/source"
	"github.com/Roro1727/airom/internal/source/dirsource"
)

// Options configures a git source. IgnoreGlobs is passed straight through to
// the underlying directory scan (the worktree, cloned or local).
type Options struct {
	IgnoreGlobs []string
}

// Provenance records what revision was scanned, for the inventory root. All
// fields are best-effort: a local path that is not a git worktree yields an
// empty Provenance and the scan still proceeds.
type Provenance struct {
	Remote string // origin URL (the clone URL for remotes; origin for locals)
	Commit string // resolved HEAD commit hash
	Dirty  bool   // worktree has uncommitted changes (locals only; needs git)
	Local  bool   // target was an existing local worktree, not a remote clone
}

// Source is the repo implementation of source.Source. It embeds the directory
// source that scans the worktree, so Walk, Resolver, and WalkUnknowns are
// delegated verbatim; only the identity/provenance methods are overridden.
type Source struct {
	*dirsource.Source

	target string
	info   source.Info
	id     string
	tmpDir string // non-empty when we cloned; removed on Close

	// Prov is the captured provenance (remote, commit, dirty state).
	Prov Provenance
}

var _ source.Source = (*Source)(nil)

// remoteURLRe matches the remote URL shapes we shallow-clone: https/http,
// ssh, git protocol, and scp-like git@host:path.
var remoteURLRe = regexp.MustCompile(`^(https?://|ssh://|git://|git@)`)

// errNoGitBinary signals that no git binary is on PATH.
var errNoGitBinary = errors.New("git binary not found on PATH")

// New prepares a git source. If target is an existing local path it is scanned
// as a directory (best-effort git provenance is captured). If target is a
// remote URL it is shallow-cloned into a temp dir which is scanned and removed
// on Close.
func New(target string, opts Options) (*Source, error) {
	if target == "" {
		return nil, fmt.Errorf("git source: empty target")
	}
	if st, err := os.Stat(target); err == nil {
		if !st.IsDir() {
			return nil, fmt.Errorf("git source %q: not a directory (point at the worktree root)", target)
		}
		return newLocal(target, opts)
	}
	if remoteURLRe.MatchString(target) {
		return newRemote(target, opts)
	}
	return nil, fmt.Errorf("git source %q: not an existing local path or a recognized remote URL (https, ssh, git://, or git@host:path)", target)
}

func newLocal(target string, opts Options) (*Source, error) {
	inner, err := dirsource.New(target, dirsource.Options{IgnoreGlobs: opts.IgnoreGlobs})
	if err != nil {
		return nil, err
	}
	prov := readProvenance(target)
	prov.Local = true
	return &Source{
		Source: inner,
		target: target,
		info:   source.Info{Kind: source.KindRepo, Target: target},
		id:     idFor(prov.Commit, target),
		Prov:   prov,
	}, nil
}

func newRemote(target string, opts Options) (*Source, error) {
	tmp, err := os.MkdirTemp("", "airom-gitclone-")
	if err != nil {
		return nil, fmt.Errorf("git source: create temp dir: %w", err)
	}
	if err := clone(target, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, fmt.Errorf("git source %q: %w", target, err)
	}
	inner, err := dirsource.New(tmp, dirsource.Options{IgnoreGlobs: opts.IgnoreGlobs})
	if err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	prov := readProvenance(tmp)
	prov.Remote = target // the URL we cloned is the authoritative remote
	return &Source{
		Source: inner,
		target: target,
		info:   source.Info{Kind: source.KindRepo, Target: target},
		id:     idFor(prov.Commit, target),
		tmpDir: tmp,
		Prov:   prov,
	}, nil
}

// idFor builds the content identity: the resolved HEAD commit when obtainable,
// else the target string.
func idFor(commit, target string) string {
	if commit != "" {
		return "git:" + commit
	}
	return "git:" + target
}

// clone shallow-clones url into dst via the git binary. dst must exist and be
// empty on entry.
//
// Deviation from the original design: a go-git PlainClone fallback is NOT
// wired in. go-git's clone/transport/object packages pull transitive
// dependencies that are absent from this module's go.sum, and the build
// constraints for this work forbid `go get`/`go mod` (see the report). The
// exec-git fast path is therefore the only clone implementation; when no git
// binary is present a clear error is returned instead of a silent fallback.
func clone(url, dst string) error {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("%w: install git or scan a local worktree path", errNoGitBinary)
	}
	// #nosec G204 -- url is the user-requested scan target and dst is our own
	// temp dir; "--" ends option parsing so a URL starting with "-" cannot be
	// read as a flag.
	cmd := exec.Command(gitBin, "clone", "--depth=1", "--single-branch", "--no-tags", "--", url, dst)
	// Never block on an interactive credential prompt for a private repo.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// readProvenance captures HEAD/remote/dirty for the worktree at dir. When a
// git binary is present it is authoritative (and the only way to compute the
// dirty flag); otherwise HEAD and origin are recovered by parsing .git files
// directly. Every step is best-effort — a non-git directory returns a zero
// Provenance.
func readProvenance(dir string) Provenance {
	if gitBin, err := exec.LookPath("git"); err == nil {
		return provenanceViaGit(gitBin, dir)
	}
	return provenanceViaFiles(dir)
}

func provenanceViaGit(gitBin, dir string) Provenance {
	var p Provenance
	run := func(args ...string) (string, bool) {
		// #nosec G204 -- gitBin is resolved from PATH and dir is our scan root.
		cmd := exec.Command(gitBin, append([]string{"-C", dir}, args...)...)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			return "", false
		}
		return strings.TrimSpace(out.String()), true
	}
	if s, ok := run("rev-parse", "HEAD"); ok {
		p.Commit = s
	}
	if s, ok := run("config", "--get", "remote.origin.url"); ok {
		p.Remote = s
	}
	if s, ok := run("status", "--porcelain"); ok {
		p.Dirty = s != ""
	}
	return p
}

// provenanceViaFiles recovers the commit and origin URL without a git binary
// by reading .git/HEAD, its target ref (loose or packed), and .git/config.
func provenanceViaFiles(dir string) Provenance {
	var p Provenance
	gitDir := filepath.Join(dir, ".git")
	head, err := os.ReadFile(filepath.Join(gitDir, "HEAD")) // #nosec G304 -- fixed path under the scan root
	if err != nil {
		return p
	}
	line := strings.TrimSpace(string(head))
	if ref, ok := strings.CutPrefix(line, "ref:"); ok {
		p.Commit = resolveRef(gitDir, strings.TrimSpace(ref))
	} else if isHash(line) {
		p.Commit = line // detached HEAD
	}
	p.Remote = originURLFromConfig(gitDir)
	return p
}

// resolveRef reads a loose ref file, falling back to packed-refs. The ref name
// comes from .git/HEAD and is validated to a plain "refs/..." path with no
// traversal before it is joined to gitDir.
func resolveRef(gitDir, ref string) string {
	if !isSafeRef(ref) {
		return ""
	}
	if data, err := os.ReadFile(filepath.Join(gitDir, filepath.FromSlash(ref))); err == nil { // #nosec G304 G703 -- ref validated by isSafeRef (refs/… , no traversal) under the .git dir
		if h := strings.TrimSpace(string(data)); isHash(h) {
			return h
		}
	}
	packed, err := os.Open(filepath.Join(gitDir, "packed-refs")) // #nosec G304 -- fixed path under the scan root
	if err != nil {
		return ""
	}
	defer func() { _ = packed.Close() }()
	sc := bufio.NewScanner(packed)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "^") {
			continue
		}
		hash, name, ok := strings.Cut(l, " ")
		if ok && name == ref && isHash(hash) {
			return hash
		}
	}
	return ""
}

// originURLFromConfig scrapes the url of [remote "origin"] from .git/config.
func originURLFromConfig(gitDir string) string {
	f, err := os.Open(filepath.Join(gitDir, "config")) // #nosec G304 -- fixed path under the scan root
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	inOrigin := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inOrigin = strings.EqualFold(line, `[remote "origin"]`)
			continue
		}
		if inOrigin {
			if v, ok := strings.CutPrefix(line, "url"); ok {
				if eq := strings.Index(v, "="); eq >= 0 {
					return strings.TrimSpace(v[eq+1:])
				}
			}
		}
	}
	return ""
}

var hashRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`) // sha1 or sha256

func isHash(s string) bool { return hashRe.MatchString(s) }

// isSafeRef accepts only a conventional "refs/..." name with no path traversal
// or absolute component, so joining it to the .git dir cannot escape.
func isSafeRef(ref string) bool {
	if ref == "" || !strings.HasPrefix(ref, "refs/") {
		return false
	}
	if strings.Contains(ref, "..") || filepath.IsAbs(filepath.FromSlash(ref)) {
		return false
	}
	return filepath.IsLocal(filepath.FromSlash(ref))
}

// Kind reports the source kind ("repo").
func (s *Source) Kind() source.Kind { return source.KindRepo }

// ID is the content identity: "git:"+commit when resolvable, else "git:"+target.
func (s *Source) ID() string { return s.id }

// Info returns the provenance root for the scan output.
func (s *Source) Info() source.Info { return s.info }

// Name returns the original scan target (URL or local path).
func (s *Source) Name() string { return s.target }

// Close closes the underlying directory source and, for remote clones, removes
// the temporary checkout.
func (s *Source) Close() error {
	err := s.Source.Close()
	if s.tmpDir != "" {
		if rerr := os.RemoveAll(s.tmpDir); rerr != nil && err == nil {
			err = fmt.Errorf("remove clone dir: %w", rerr)
		}
	}
	return err
}
