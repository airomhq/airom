package frozen

import (
	"bytes"
	"context"
	"testing"

	"github.com/airomhq/airom/pkg/airom/detect"
)

// A real frozen app is hundreds of megabytes, far past --max-file-size. This
// pins that size alone never keeps the archive from being read: the detector
// works over ReaderAt, so the bootloader's bulk is seeked past, not loaded.
func TestPyInstallerHandlesALargeBinary(t *testing.T) {
	pyz := buildPYZ(t, map[string][]byte{
		"crawl4ai": {}, "crawl4ai.__version__": pycWith("0.7.8"),
	})
	big := make([]byte, 64<<20) // 64 MiB of bootloader
	copy(big, elfPrefix())
	bin := buildOnefile(t, big, []member{{name: "PYZ-00.pyz", typ: 'z', body: pyz}})

	f := detect.NewFile(
		detect.FileRef{Path: "opt/app", Size: int64(len(bin))},
		bin[:32],
		detect.FileProviders{
			// Content deliberately reports a 1 MiB truncated prefix, as the
			// engine would: anything relying on it would see nothing.
			Content:  func() ([]byte, bool, error) { return bin[:1<<20], true, nil },
			ReaderAt: func() (detect.ReaderAtCloser, error) { return nopCloser{bytes.NewReader(bin)}, nil },
		},
	)
	got, err := NewPyInstaller().DetectFile(context.Background(), f)
	if err != nil {
		t.Fatalf("DetectFile on a %d-byte binary: %v", len(bin), err)
	}
	if len(got) != 1 || got[0].Claim.Name != "crawl4ai" || got[0].Claim.Version != "0.7.8" {
		t.Fatalf("got %+v, want crawl4ai 0.7.8 from a 64 MiB binary", got)
	}
}
