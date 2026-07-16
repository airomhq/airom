package dirsource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Roro1727/airom/internal/source"
)

// buildFixture creates:
//
//	root/
//	  .gitignore            ("*.log", "build/")
//	  app.py
//	  keep.log              (ignored by *.log)
//	  build/out.txt         (ignored dir)
//	  node_modules/x.js     (default skip)
//	  .git/config           (default skip)
//	  vendor/lib.go         (default skip)
//	  sub/
//	    .gitignore          ("secret.txt", "*.tmp")
//	    .airomignore        ("!keep.tmp")   — re-inclusion on top of .gitignore
//	    b.ts
//	    secret.txt          (ignored by nested .gitignore)
//	    keep.tmp            (re-included by .airomignore)
//	    drop.tmp            (ignored)
//	  skipme/c.py           (user --ignore glob)
func buildFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".gitignore", "*.log\nbuild/\n")
	write("app.py", "import openai\n")
	write("keep.log", "log\n")
	write("build/out.txt", "artifact\n")
	write("node_modules/x.js", "js\n")
	write(".git/config", "[core]\n")
	write("vendor/lib.go", "package lib\n")
	write("sub/.gitignore", "secret.txt\n*.tmp\n")
	write("sub/.airomignore", "!keep.tmp\n")
	write("sub/b.ts", "const x = 1\n")
	write("sub/secret.txt", "shh\n")
	write("sub/keep.tmp", "kept\n")
	write("sub/drop.tmp", "dropped\n")
	write("skipme/c.py", "x = 1\n")
	return root
}

func walkPaths(t *testing.T, s *Source) []string {
	t.Helper()
	var (
		mu    sync.Mutex
		paths []string
	)
	err := s.Walk(context.Background(), func(en source.Entry) error {
		mu.Lock()
		paths = append(paths, en.Ref.Path)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	sort.Strings(paths)
	return paths
}

func TestWalkIgnoreSemantics(t *testing.T) {
	root := buildFixture(t)
	s, err := New(root, Options{IgnoreGlobs: []string{"skipme/**"}})
	if err != nil {
		t.Fatal(err)
	}

	got := walkPaths(t, s)
	want := []string{
		".gitignore",
		"app.py",
		"sub/.airomignore",
		"sub/.gitignore",
		"sub/b.ts",
		"sub/keep.tmp", // .airomignore re-inclusion over .gitignore *.tmp
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("walk mismatch:\n got:  %v\n want: %v", got, want)
	}
	if len(s.WalkUnknowns()) != 0 {
		t.Errorf("unexpected unknowns: %v", s.WalkUnknowns())
	}
}

func TestSymlinksNeverFollowed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "real.py"), []byte("x=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// dir symlink cycle + file symlink
	if err := os.Symlink(root, filepath.Join(root, "loop")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := os.Symlink(filepath.Join(root, "real.py"), filepath.Join(root, "link.py")); err != nil {
		t.Fatal(err)
	}

	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := walkPaths(t, s)
	if strings.Join(got, ",") != "real.py" {
		t.Errorf("walk = %v, want only real.py (symlinks skipped, no cycle hang)", got)
	}
}

func TestPermissionDeniedDegradesToUnknown(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission semantics unavailable")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.py"), []byte("x=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "hidden.py"), []byte("x=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := walkPaths(t, s) // must not error (P6)
	if strings.Join(got, ",") != "ok.py" {
		t.Errorf("walk = %v, want ok.py only", got)
	}
	if len(s.WalkUnknowns()) == 0 {
		t.Error("permission failure produced no Unknown record")
	}
}

func TestWalkCancellation(t *testing.T) {
	root := buildFixture(t)
	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = s.Walk(ctx, func(source.Entry) error { return nil })
	if err == nil {
		t.Error("want context error from canceled walk")
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New("/does/not/exist", Options{}); err == nil {
		t.Error("want error for missing root")
	}
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f, Options{}); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("err = %v, want not-a-directory", err)
	}
	if _, err := New(t.TempDir(), Options{IgnoreGlobs: []string{"[bad"}}); err == nil {
		t.Error("want error for invalid glob")
	}
}

func TestResolver(t *testing.T) {
	root := buildFixture(t)
	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := s.Resolver()

	refs, err := r.FilesByGlob(context.Background(), "**/*.ts")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Path != "sub/b.ts" {
		t.Errorf("FilesByGlob = %+v, want sub/b.ts", refs)
	}

	// The resolver honors ignore rules: a phase-2 glob can never surface
	// what phase 1 could not see.
	refs, err = r.FilesByGlob(context.Background(), "**/*.log", "**/secret.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("FilesByGlob leaked ignored files: %+v", refs)
	}

	rc, err := r.Open("app.py")
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()

	if _, err := r.Open("../outside.txt"); err == nil {
		t.Error("path traversal not rejected")
	}
	if _, err := r.Open("/etc/passwd"); err == nil {
		t.Error("absolute path not rejected")
	}

	ref, err := r.Stat("sub/b.ts")
	if err != nil || ref.Size == 0 {
		t.Errorf("Stat = %+v, %v", ref, err)
	}
}

// TestConcurrentFilesByGlob is the walk-local-state regression: concurrent
// resolver pulls (the §8 phase-2 usage) previously crashed the process by
// resetting shared traversal state mid-walk.
func TestConcurrentFilesByGlob(t *testing.T) {
	root := buildFixture(t)
	s, err := New(root, Options{IgnoreGlobs: []string{"skipme/**"}})
	if err != nil {
		t.Fatal(err)
	}
	r := s.Resolver()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				refs, err := r.FilesByGlob(context.Background(), "**/*.py")
				if err != nil {
					errs <- err
					return
				}
				if len(refs) != 1 || refs[0].Path != "app.py" {
					errs <- fmt.Errorf("got %+v, want [app.py]", refs)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestFilesByGlobPreservesWalkUnknowns: resolver pulls must never clobber
// the phase-1 walk's Unknown records.
func TestFilesByGlobPreservesWalkUnknowns(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission semantics unavailable")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.py"), []byte("x=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Walk(context.Background(), func(source.Entry) error { return nil }); err != nil {
		t.Fatal(err)
	}
	before := len(s.WalkUnknowns())
	if before == 0 {
		t.Fatal("fixture produced no walk unknowns")
	}
	if _, err := s.Resolver().FilesByGlob(context.Background(), "**/*.py"); err != nil {
		t.Fatal(err)
	}
	if after := len(s.WalkUnknowns()); after != before {
		t.Errorf("WalkUnknowns went %d -> %d after a resolver pull", before, after)
	}
}

// TestDoubleStarReinclusion: the `dir/**` + `!dir/keep` idiom must keep
// what git keeps (go-git's raw matcher would prune the dir itself).
func TestDoubleStarReinclusion(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		".gitignore":    "logs/**\n!logs/keep.txt\n",
		"logs/drop.txt": "x",
		"logs/keep.txt": "x",
		"app.py":        "x",
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := walkPaths(t, s)
	want := []string{".gitignore", "app.py", "logs/keep.txt"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("walk = %v, want %v", got, want)
	}
}

// TestDefaultSkipsNotOverridable: "always-on" means always-on — no user
// negation can re-include VCS/dependency internals.
func TestDefaultSkipsNotOverridable(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		".gitignore":        "!.git/\n!node_modules/\n!vendor/\n",
		".git/config":       "[core]\n",
		"node_modules/x.js": "x",
		"vendor/lib.go":     "x",
		"app.py":            "x",
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := walkPaths(t, s)
	want := []string{".gitignore", "app.py"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("walk = %v, want %v (defaults must not be overridable)", got, want)
	}
}

// TestResolverHonorsIgnores: Open/Stat must reject what Walk would skip.
func TestResolverHonorsIgnores(t *testing.T) {
	root := buildFixture(t)
	s, err := New(root, Options{IgnoreGlobs: []string{"skipme/**"}})
	if err != nil {
		t.Fatal(err)
	}
	r := s.Resolver()

	for _, rel := range []string{"keep.log", "sub/secret.txt", "node_modules/x.js", "skipme/c.py"} {
		if _, err := r.Open(rel); err == nil {
			t.Errorf("Open(%q) succeeded on an ignored path", rel)
		}
		if _, err := r.Stat(rel); err == nil {
			t.Errorf("Stat(%q) succeeded on an ignored path", rel)
		}
	}
	// Re-included path stays reachable.
	if _, err := r.Stat("sub/keep.tmp"); err != nil {
		t.Errorf("Stat(sub/keep.tmp) = %v, want ok (re-included)", err)
	}
}

// TestResolverSymlinkContainment: a symlink inside the root pointing outside
// must not be openable through the resolver.
func TestResolverSymlinkContainment(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(root, "link.txt")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := s.Resolver()
	if _, err := r.Open("link.txt"); err == nil {
		t.Error("Open followed a symlink out of the scan root")
	}
	if _, err := r.Stat("link.txt"); err == nil {
		t.Error("Stat followed a symlink out of the scan root")
	}
}

// TestUnreadableRootIsFatal: docs/cli.md exit-code contract — an unreadable
// root is source-acquisition failure, not a silent empty scan.
func TestUnreadableRootIsFatal(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission semantics unavailable")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "x.py"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	s, err := New(root, Options{})
	if err != nil {
		// Stat may already fail depending on parent perms — also fatal, also fine.
		return
	}
	if err := s.Walk(context.Background(), func(source.Entry) error { return nil }); err == nil {
		t.Error("Walk of unreadable root succeeded; want fatal error")
	}
}

// TestIgnoreFileBOM: git strips a leading UTF-8 BOM; so must we.
func TestIgnoreFileBOM(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("\xef\xbb\xbf*.log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "x.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := walkPaths(t, s)
	if strings.Join(got, ",") != ".gitignore" {
		t.Errorf("walk = %v; BOM'd first pattern did not match", got)
	}
}

// TestCaseFoldIgnore: on core.ignorecase platforms, pattern case must not
// matter (mirrors the user's git behavior).
func TestCaseFoldIgnore(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("case folding only on core.ignorecase platforms")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("*.LOG\nBuild/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for rel, c := range map[string]string{"x.log": "x", "build/y.txt": "y", "app.py": "z"} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := walkPaths(t, s)
	want := []string{".gitignore", "app.py"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("walk = %v, want %v", got, want)
	}
}
