package frozen

import (
	"encoding/binary"
	"os"
	"testing"
)

// TestParsePYZAgainstRealArchive parses a module directory taken verbatim out
// of a binary built by PyInstaller 6.21.
//
// It exists because the hand-built fixtures cannot catch a wrong belief about
// the format: the builder and the parser were written from the same assumption,
// so they agreed with each other while returning nothing for every genuine
// binary. Four kilobytes of real marshal output is the cheapest possible guard
// against that happening again — no Python in CI, no megabytes in the repo.
func TestParsePYZAgainstRealArchive(t *testing.T) {
	dir, err := os.ReadFile("testdata/real-pyz-directory.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// Wrap the directory in a PYZ header pointing straight at it.
	pyz := make([]byte, pyzHeaderLen)
	copy(pyz, pyzMagic)
	binary.LittleEndian.PutUint32(pyz[4:8], 0x0a0d0e2b)
	binary.BigEndian.PutUint32(pyz[8:12], uint32(pyzHeaderLen))
	pyz = append(pyz, dir...)

	p, err := ParsePYZ(pyz)
	if err != nil {
		t.Fatalf("ParsePYZ on real PyInstaller output: %v", err)
	}
	// The archive this came from freezes 133 modules, which fold to 75
	// top-level packages — most of the stdlib the bootloader pulls in, plus the
	// application's own. `os` and `types` are deliberately NOT expected: they
	// are frozen into the interpreter itself, not listed here.
	if len(p.Modules) != 133 {
		t.Errorf("modules = %d, want the 133 this archive lists", len(p.Modules))
	}
	for _, want := range []string{"crawl4ai", "crawl4ai.__version__", "json", "urllib.parse"} {
		if _, ok := p.Lookup(want); !ok {
			t.Errorf("module %q missing; the directory did not decode correctly", want)
		}
	}
	if got := len(p.TopLevelPackages()); got != 75 {
		t.Errorf("top-level packages = %d, want 75", got)
	}
	// The reason this fixture exists: a package whose version lives only in the
	// archive must be recoverable from it.
	m, ok := p.Lookup("crawl4ai.__version__")
	if !ok {
		t.Fatal("crawl4ai.__version__ not in the real directory")
	}
	if m.Length <= 0 {
		t.Errorf("crawl4ai.__version__ length = %d, want a real body", m.Length)
	}
}

// TestParsePYZAcceptsTheDictShape covers the other branch, which older writers
// and most descriptions of the format produce.
func TestParsePYZAcceptsTheDictShape(t *testing.T) {
	dir := marshalDirectoryDict(map[string][2]int64{"crawl4ai": {pyzHeaderLen, 4}})
	pyz := make([]byte, pyzHeaderLen)
	copy(pyz, pyzMagic)
	binary.BigEndian.PutUint32(pyz[8:12], uint32(pyzHeaderLen+4))
	pyz = append(pyz, []byte("body")...)
	pyz = append(pyz, dir...)

	p, err := ParsePYZ(pyz)
	if err != nil {
		t.Fatalf("ParsePYZ on the dict shape: %v", err)
	}
	if _, ok := p.Lookup("crawl4ai"); !ok {
		t.Error("dict-shaped directory did not decode")
	}
}
