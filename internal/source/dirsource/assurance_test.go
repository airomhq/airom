package dirsource

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/airomhq/airom/internal/source"
)

// TestWalkStatsCountsExclusions pins the assurance contract: what the walk
// deliberately skipped is counted, and a pruned directory counts once — the
// walker cannot count files it never enumerated.
func TestWalkStatsCountsExclusions(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.py", "print('hi')\n")
	write(".gitignore", "secret.txt\n")
	write("secret.txt", "ignored by rule\n") // 1 ignored file
	write("node_modules/x/index.js", "js\n") // default skip: pruned dir
	write("vendor/lib.go", "package lib\n")  // default skip: pruned dir

	s, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var walked []string
	if err := s.Walk(context.Background(), func(e source.Entry) error {
		walked = append(walked, e.Ref.Path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	st := s.WalkStats()
	// .gitignore itself is walked; secret.txt is the one ignored FILE.
	if st.FilesIgnored != 1 {
		t.Errorf("FilesIgnored = %d, want 1 (secret.txt); walked: %v", st.FilesIgnored, walked)
	}
	// node_modules and vendor prune as directories: one line each, and their
	// contents must not inflate the file counter.
	if st.DirsPruned != 2 {
		t.Errorf("DirsPruned = %d, want 2 (node_modules, vendor)", st.DirsPruned)
	}
	for _, p := range walked {
		if p == "secret.txt" || p == "node_modules/x/index.js" {
			t.Errorf("excluded path %q was walked anyway", p)
		}
	}
}
