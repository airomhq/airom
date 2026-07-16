package imagesource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/source"
)

// tf is one tar entry in a layer.
type tf struct {
	name    string
	content string
	kind    byte // 0 => regular file
}

// layerTar builds an uncompressed layer tar from entries.
func layerTar(t *testing.T, files []tf) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		typ := f.kind
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     f.name,
			Mode:     0o644,
			Size:     int64(len(f.content)),
			Typeflag: typ,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(in); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// dockerSave writes a docker-save archive with the given layers (base→top) and
// returns its path.
func dockerSave(t *testing.T, layers [][]byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	tw := tar.NewWriter(f)

	write := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}

	write("config.json", []byte(`{"architecture":"amd64","os":"linux"}`))
	layerNames := make([]string, len(layers))
	for i, l := range layers {
		name := "layer" + itoa(i) + ".tar"
		layerNames[i] = name
		write(name, l)
	}
	manifest, _ := json.Marshal([]dockerManifest{{Config: "config.json", Layers: layerNames}})
	write("manifest.json", manifest)

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func readEntry(t *testing.T, e source.Entry) string {
	t.Helper()
	rc, err := e.Open()
	if err != nil {
		t.Fatalf("Open %q: %v", e.Ref.Path, err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %q: %v", e.Ref.Path, err)
	}
	return string(data)
}

func collect(t *testing.T, s *Source) map[string]source.Entry {
	t.Helper()
	out := map[string]source.Entry{}
	if err := s.Walk(context.Background(), func(e source.Entry) error {
		out[e.Ref.Path] = e
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return out
}

func TestWalkYieldsFiles(t *testing.T) {
	t.Parallel()
	layer := layerTar(t, []tf{
		{name: "a.txt", content: "hello"},
		{name: "dir/b.py", content: "print(1)\n"},
		{name: "dir", kind: tar.TypeDir}, // dirs are skipped
	})
	p := dockerSave(t, [][]byte{layer})

	s, err := New(p, Options{}) // New delegates to NewFromTar for a local path
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.Kind() != source.KindImage {
		t.Errorf("Kind = %q, want image", s.Kind())
	}
	if info := s.Info(); info.Kind != source.KindImage || info.Target != p {
		t.Errorf("Info = %+v", info)
	}

	files := collect(t, s)
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2: %v", len(files), keys(files))
	}
	if got := readEntry(t, files["a.txt"]); got != "hello" {
		t.Errorf("a.txt = %q, want hello", got)
	}
	if got := readEntry(t, files["dir/b.py"]); got != "print(1)\n" {
		t.Errorf("dir/b.py = %q", got)
	}
	if files["dir/b.py"].Ref.Language != classify.LangPython {
		t.Errorf("b.py language = %q, want python", files["dir/b.py"].Ref.Language)
	}

	// ReaderAt must report not-seekable for stream-backed entries.
	if _, err := files["a.txt"].ReaderAt(); !errors.Is(err, ErrNotSeekable) {
		t.Errorf("ReaderAt err = %v, want ErrNotSeekable", err)
	}

	// Open is reusable (spool-backed): a second read yields the same bytes.
	if got := readEntry(t, files["a.txt"]); got != "hello" {
		t.Errorf("a.txt reread = %q", got)
	}

	// ID is a computed image digest (sha256 of the config), not the fallback.
	if id := s.ID(); len(id) < 8 || id[:7] != "sha256:" {
		t.Errorf("ID = %q, want a sha256: digest", id)
	}
}

func TestWhiteout(t *testing.T) {
	t.Parallel()
	base := layerTar(t, []tf{
		{name: "old.txt", content: "old"},
		{name: "keep.txt", content: "keep"},
	})
	top := layerTar(t, []tf{
		{name: ".wh.old.txt", content: ""},
		{name: "new.txt", content: "new"},
	})
	s, err := NewFromTar(dockerSave(t, [][]byte{base, top}), Options{})
	if err != nil {
		t.Fatalf("NewFromTar: %v", err)
	}
	defer func() { _ = s.Close() }()

	got := sortedKeys(collect(t, s))
	want := []string{"keep.txt", "new.txt"}
	if !equal(got, want) {
		t.Errorf("whiteout result = %v, want %v", got, want)
	}
}

func TestOpaqueWhiteout(t *testing.T) {
	t.Parallel()
	base := layerTar(t, []tf{
		{name: "dir/a", content: "a"},
		{name: "dir/b", content: "b"},
		{name: "top.txt", content: "t"},
	})
	top := layerTar(t, []tf{
		{name: "dir/.wh..wh..opq", content: ""},
		{name: "dir/c", content: "c"},
	})
	s, err := NewFromTar(dockerSave(t, [][]byte{base, top}), Options{})
	if err != nil {
		t.Fatalf("NewFromTar: %v", err)
	}
	defer func() { _ = s.Close() }()

	got := sortedKeys(collect(t, s))
	want := []string{"dir/c", "top.txt"}
	if !equal(got, want) {
		t.Errorf("opaque result = %v, want %v", got, want)
	}
}

func TestTopLayerOverrides(t *testing.T) {
	t.Parallel()
	base := layerTar(t, []tf{{name: "x.txt", content: "old"}})
	top := layerTar(t, []tf{{name: "x.txt", content: "new"}})
	s, err := NewFromTar(dockerSave(t, [][]byte{base, top}), Options{})
	if err != nil {
		t.Fatalf("NewFromTar: %v", err)
	}
	defer func() { _ = s.Close() }()

	files := collect(t, s)
	if got := readEntry(t, files["x.txt"]); got != "new" {
		t.Errorf("x.txt = %q, want new (top layer wins)", got)
	}
}

func TestGzipLayer(t *testing.T) {
	t.Parallel()
	raw := layerTar(t, []tf{{name: "g.txt", content: "gzipped"}})
	s, err := NewFromTar(dockerSave(t, [][]byte{gzipBytes(t, raw)}), Options{})
	if err != nil {
		t.Fatalf("NewFromTar: %v", err)
	}
	defer func() { _ = s.Close() }()

	files := collect(t, s)
	if got := readEntry(t, files["g.txt"]); got != "gzipped" {
		t.Errorf("g.txt = %q, want gzipped", got)
	}
}

func TestSpillToDisk(t *testing.T) {
	t.Parallel()
	big := "0123456789ABCDEF0123456789ABCDEF" // 32 bytes, > MaxMemPerFile below
	layer := layerTar(t, []tf{{name: "big.bin", content: big}})
	// Force the in-memory cap low so this file spills to a temp file, but keep
	// the disk cap high enough to hold it in full.
	s, err := NewFromTar(dockerSave(t, [][]byte{layer}), Options{MaxMemPerFile: 8, MaxDiskPerFile: 1 << 20})
	if err != nil {
		t.Fatalf("NewFromTar: %v", err)
	}
	defer func() { _ = s.Close() }()

	files := collect(t, s)
	e := files["big.bin"]
	if got := readEntry(t, e); got != big {
		t.Errorf("big.bin spilled content = %q, want full", got)
	}
	// Confirm it really went to disk, not memory.
	if fe := s.byPath["big.bin"]; fe.sp.tmpPath == "" {
		t.Errorf("expected big.bin to spill to a temp file, got mem=%d", len(fe.sp.mem))
	}
	// Clean removes the temp dir.
	tmp := s.tmpDir
	if err := s.Clean(); err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("temp dir %q survived Clean: %v", tmp, err)
	}
}

func TestHeaderOnlyOversized(t *testing.T) {
	t.Parallel()
	content := "ABCDEFGHIJKLMNOP" // 16 bytes
	layer := layerTar(t, []tf{{name: "huge.bin", content: content}})
	// Both mem and disk caps are 4, header cap is 4: the file is too big for
	// either spool and is surfaced header-only (first 4 bytes).
	s, err := NewFromTar(dockerSave(t, [][]byte{layer}),
		Options{MaxMemPerFile: 4, MaxDiskPerFile: 4, HeaderCap: 4})
	if err != nil {
		t.Fatalf("NewFromTar: %v", err)
	}
	defer func() { _ = s.Close() }()

	files := collect(t, s)
	if got := readEntry(t, files["huge.bin"]); got != "ABCD" {
		t.Errorf("huge.bin header-only = %q, want ABCD", got)
	}
	if len(s.WalkUnknowns()) == 0 {
		t.Errorf("expected an Unknown recording the truncation")
	}
}

func TestMemBudgetSpills(t *testing.T) {
	t.Parallel()
	// Two 6-byte files; per-file mem cap 8 allows memory, but the 10-byte total
	// budget forces the second to spill to disk.
	layer := layerTar(t, []tf{
		{name: "one.txt", content: "aaaaaa"},
		{name: "two.txt", content: "bbbbbb"},
	})
	s, err := NewFromTar(dockerSave(t, [][]byte{layer}),
		Options{MaxMemPerFile: 8, MemBudget: 10, MaxDiskPerFile: 1 << 20})
	if err != nil {
		t.Fatalf("NewFromTar: %v", err)
	}
	defer func() { _ = s.Close() }()

	files := collect(t, s)
	if readEntry(t, files["one.txt"]) != "aaaaaa" || readEntry(t, files["two.txt"]) != "bbbbbb" {
		t.Errorf("content mismatch after budget spill")
	}
	memCount, diskCount := 0, 0
	for _, fe := range s.ordered {
		if fe.sp.mem != nil {
			memCount++
		} else if fe.sp.tmpPath != "" {
			diskCount++
		}
	}
	if memCount != 1 || diskCount != 1 {
		t.Errorf("mem=%d disk=%d, want 1 and 1 (budget forced one spill)", memCount, diskCount)
	}
}

func TestResolver(t *testing.T) {
	t.Parallel()
	layer := layerTar(t, []tf{
		{name: "app/main.py", content: "print()"},
		{name: "app/data.json", content: "{}"},
	})
	s, err := NewFromTar(dockerSave(t, [][]byte{layer}), Options{})
	if err != nil {
		t.Fatalf("NewFromTar: %v", err)
	}
	defer func() { _ = s.Close() }()

	r := s.Resolver()
	refs, err := r.FilesByGlob(context.Background(), "**/*.py")
	if err != nil {
		t.Fatalf("FilesByGlob: %v", err)
	}
	if len(refs) != 1 || refs[0].Path != "app/main.py" {
		t.Errorf("FilesByGlob = %+v, want [app/main.py]", refs)
	}
	rc, err := r.Open("app/data.json")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(data) != "{}" {
		t.Errorf("Open content = %q", data)
	}
	ref, err := r.Stat("app/main.py")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if ref.Language != classify.LangPython {
		t.Errorf("Stat language = %q, want python", ref.Language)
	}
	if _, err := r.Stat("missing"); err == nil {
		t.Errorf("Stat(missing) = nil error, want not found")
	}
}

func TestZstdLayerRecordedUnknown(t *testing.T) {
	t.Parallel()
	// A layer beginning with the zstd magic is unsupported and must be recorded
	// as an Unknown rather than crashing the walk.
	zstd := append([]byte{0x28, 0xb5, 0x2f, 0xfd}, []byte("garbage")...)
	s, err := NewFromTar(dockerSave(t, [][]byte{zstd}), Options{})
	if err != nil {
		t.Fatalf("NewFromTar: %v", err)
	}
	defer func() { _ = s.Close() }()

	if files := collect(t, s); len(files) != 0 {
		t.Errorf("got %d files from a zstd layer, want 0", len(files))
	}
	if len(s.WalkUnknowns()) == 0 {
		t.Errorf("expected an Unknown for the unsupported zstd layer")
	}
}

func TestNewLiveRefUnsupported(t *testing.T) {
	t.Parallel()
	_, err := New("registry.example.com/acme/app:latest", Options{})
	if err == nil {
		t.Fatal("New(registry ref) = nil error, want unsupported-live-pull error")
	}
}

func TestNonImagePathErrors(t *testing.T) {
	t.Parallel()
	// A tar that is not a docker-save/OCI archive fails materialization.
	dir := t.TempDir()
	p := filepath.Join(dir, "plain.tar")
	f, _ := os.Create(p)
	tw := tar.NewWriter(f)
	_ = tw.WriteHeader(&tar.Header{Name: "hello.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	_ = f.Close()

	s, err := NewFromTar(p, Options{})
	if err != nil {
		t.Fatalf("NewFromTar: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Walk(context.Background(), func(source.Entry) error { return nil }); err == nil {
		t.Errorf("Walk over a non-image tar = nil error, want acquisition failure")
	}
}

func FuzzNewFromTar(f *testing.F) {
	// Seed with a valid docker-save archive and some junk.
	valid, err := os.ReadFile(dockerSave(&testing.T{}, [][]byte{layerTarFuzz()}))
	if err == nil {
		f.Add(valid)
	}
	f.Add([]byte("not a tar"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		p := filepath.Join(dir, "in.tar")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Skip()
		}
		s, err := NewFromTar(p, Options{MaxMemPerFile: 1 << 10, MaxDiskPerFile: 1 << 12, HeaderCap: 128})
		if err != nil {
			return
		}
		defer func() { _ = s.Close() }()
		// Must never panic; errors are fine.
		_ = s.Walk(context.Background(), func(e source.Entry) error {
			if e.Open != nil {
				if rc, err := e.Open(); err == nil {
					_, _ = io.Copy(io.Discard, rc)
					_ = rc.Close()
				}
			}
			return nil
		})
	})
}

func layerTarFuzz() []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "f.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.Close()
	return buf.Bytes()
}

// ── small helpers ───────────────────────────────────────────────────────────

func keys(m map[string]source.Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortedKeys(m map[string]source.Entry) []string {
	out := keys(m)
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
