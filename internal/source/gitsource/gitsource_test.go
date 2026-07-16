package gitsource

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Roro1727/airom/internal/source"
)

// walkPaths runs a Walk and returns the sorted list of emitted paths.
func walkPaths(t *testing.T, s source.Source) []string {
	t.Helper()
	var got []string
	if err := s.Walk(context.Background(), func(e source.Entry) error {
		got = append(got, e.Ref.Path)
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	sort.Strings(got)
	return got
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLocalPathDelegation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n")
	writeFile(t, dir, "pkg/util.py", "print(1)\n")
	writeFile(t, dir, "README.md", "# hi\n")

	s, err := New(dir, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.Kind() != source.KindRepo {
		t.Errorf("Kind = %q, want %q", s.Kind(), source.KindRepo)
	}
	if info := s.Info(); info.Kind != source.KindRepo || info.Target != dir {
		t.Errorf("Info = %+v, want {repo %q}", info, dir)
	}
	if s.Name() != dir {
		t.Errorf("Name = %q, want %q", s.Name(), dir)
	}
	// Plain (non-git) dir: no commit, so ID falls back to the target.
	if got, want := s.ID(), "git:"+dir; got != want {
		t.Errorf("ID = %q, want %q", got, want)
	}
	if s.Prov.Commit != "" {
		t.Errorf("Prov.Commit = %q, want empty for non-git dir", s.Prov.Commit)
	}
	if !s.Prov.Local {
		t.Errorf("Prov.Local = false, want true for a local path")
	}

	got := walkPaths(t, s)
	want := []string{"README.md", "main.go", "pkg/util.py"}
	if len(got) != len(want) {
		t.Fatalf("Walk paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Walk paths = %v, want %v", got, want)
		}
	}

	// Resolver is delegated to dirsource.
	refs, err := s.Resolver().FilesByGlob(context.Background(), "**/*.py")
	if err != nil {
		t.Fatalf("FilesByGlob: %v", err)
	}
	if len(refs) != 1 || refs[0].Path != "pkg/util.py" {
		t.Errorf("FilesByGlob = %+v, want [pkg/util.py]", refs)
	}
}

// git runs a git subcommand in dir, failing the test on error.
func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func TestLocalGitProvenance(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q", "-b", "main")
	writeFile(t, dir, "a.txt", "hello\n")
	gitCmd(t, dir, "add", "a.txt")
	gitCmd(t, dir, "commit", "-q", "-m", "init")

	// Read the committed hash for comparison.
	head, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	commit := strings.TrimSpace(string(head))

	s, err := New(dir, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.Prov.Commit != commit {
		t.Errorf("Prov.Commit = %q, want %q", s.Prov.Commit, commit)
	}
	if want := "git:" + commit; s.ID() != want {
		t.Errorf("ID = %q, want %q", s.ID(), want)
	}
	if s.Prov.Dirty {
		t.Errorf("Prov.Dirty = true, want false for a clean worktree")
	}

	// An uncommitted change should register as dirty on a fresh source.
	writeFile(t, dir, "b.txt", "uncommitted\n")
	s2, err := New(dir, Options{})
	if err != nil {
		t.Fatalf("New (dirty): %v", err)
	}
	defer func() { _ = s2.Close() }()
	if !s2.Prov.Dirty {
		t.Errorf("Prov.Dirty = false, want true after adding an untracked file")
	}
}

func TestNewErrors(t *testing.T) {
	t.Parallel()
	if _, err := New("", Options{}); err == nil {
		t.Error("New(\"\") = nil error, want error")
	}
	// A non-existent, non-URL target is neither a path nor a remote.
	if _, err := New("/no/such/path/airom-xyz", Options{}); err == nil {
		t.Error("New(nonexistent) = nil error, want error")
	}
	// A regular file is not a worktree root.
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f, Options{}); err == nil {
		t.Error("New(file) = nil error, want error")
	}
}

func TestRemoteURLDetection(t *testing.T) {
	t.Parallel()
	// These are recognized as remote URLs and routed to the clone path. We
	// point at an unroutable .invalid host (RFC 6761: guaranteed to not
	// resolve) so the clone fails fast without meaningful network egress. The
	// assertion is only that detection reached the clone path (a clone error
	// mentioning the target), not a "not a path/URL" rejection.
	for _, url := range []string{
		"https://airom.invalid/does-not-exist.git",
		"git@airom.invalid:acme/x.git",
	} {
		_, err := New(url, Options{})
		if err == nil {
			t.Errorf("New(%q) = nil error, want clone failure", url)
			continue
		}
		if got := err.Error(); !strings.Contains(got, url) {
			t.Errorf("New(%q) error = %q, want it to mention the target", url, got)
		}
	}
}
