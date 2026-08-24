package bench

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestExtractSkipsPaxGlobalHeader: every tarball git produces opens with a
// pax_global_header carrying the commit SHA, and GitHub's codeload archives
// all have one. Refusing it rejected real corpus snapshots outright, which is
// how the first Tier R entry failed to load. It is metadata, not a file, so
// it extracts to nothing and the scan proceeds.
func TestExtractSkipsPaxGlobalHeader(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// Exactly what git writes: the entry carries the commit SHA as a PAX
	// comment record, and Go's writer requires PAXRecords for this type.
	if err := tw.WriteHeader(&tar.Header{
		Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader,
		PAXRecords: map[string]string{"comment": "d318b683471101618febed18996405ad26462110"},
	}); err != nil {
		t.Fatal(err)
	}
	body := []byte("openai==1.0.0\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: "repo-abc123/requirements.txt", Typeflag: tar.TypeReg,
		Size: int64(len(body)), Mode: 0o644,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	for _, c := range []io.Closer{tw, gz} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}

	dir := t.TempDir()
	arc := filepath.Join(dir, "snapshot.tar.gz")
	if err := os.WriteFile(arc, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := extractTarGz(arc, out); err != nil {
		t.Fatalf("extract rejected a normal git tarball: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(out, "repo-abc123", "requirements.txt"))
	if err != nil {
		t.Fatalf("the real file did not extract: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("content = %q, want %q", got, body)
	}
	if _, err := os.Stat(filepath.Join(out, "pax_global_header")); err == nil {
		t.Error("pax_global_header was written as a file; it is metadata")
	}
}
