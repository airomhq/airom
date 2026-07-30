package frozen

import (
	"bytes"
	"context"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

// onefile builds a frozen binary bundling the three cases the detector has to
// tell apart, then hands it to the detector the way the engine would.
func onefile(t *testing.T) []detect.Finding {
	t.Helper()
	pyz := buildPYZ(t, map[string][]byte{
		// (i) versioned by a bundled dist-info
		"litellm":      pycWith("9.9.9"), // must LOSE to the metadata below
		"litellm.main": {},
		// (ii) no dist-info at all; only __version__ — the crawl4ai case
		"crawl4ai":                  {},
		"crawl4ai.__version__":      pycWith("0.7.8"),
		"crawl4ai.async_webcrawler": {},
		// (iii) neither metadata nor a readable version
		"fastmcp":        {},
		"fastmcp.server": {},
		// a placeholder version, which must be ignored rather than reported
		"agno":             {},
		"agno.__version__": pycWith("0.0.0"),
		// bundled but not AI: must never reach the AIBOM
		"numpy":   {},
		"click":   {},
		"certifi": {},
	})
	bin := buildOnefile(t, elfPrefix(), []member{
		{name: "PYZ-00.pyz", typ: 'z', body: pyz},
		{
			name: "litellm-1.79.0.dist-info/METADATA", typ: 'x',
			body: []byte("Metadata-Version: 2.1\nName: litellm\nVersion: 1.79.0\n\ndesc\n"),
		},
	})

	f := detect.NewFile(
		detect.FileRef{Path: "opt/motadata-app", Size: int64(len(bin))},
		bin[:32],
		detect.FileProviders{
			Content:  func() ([]byte, bool, error) { return bin, false, nil },
			ReaderAt: func() (detect.ReaderAtCloser, error) { return nopCloser{bytes.NewReader(bin)}, nil },
		},
	)
	got, err := NewPyInstaller().DetectFile(context.Background(), f)
	if err != nil {
		t.Fatalf("DetectFile: %v", err)
	}
	return got
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func TestPyInstallerResolvesEachVersionTier(t *testing.T) {
	got := onefile(t)
	by := map[string]detect.Finding{}
	for _, f := range got {
		by[f.Claim.Name] = f
	}

	cases := []struct {
		name    string
		version string
		conf    airom.Confidence
		why     string
	}{
		// A bundled dist-info outranks the module's own literal, which is why
		// the fixture's litellm module claims 9.9.9 and must not win.
		{"litellm", "1.79.0", confMetadata, "dist-info"},
		// The only path that can version crawl4ai: it ships no dist-info.
		{"crawl4ai", "0.7.8", confVersionAttr, "__version__"},
		// Present, unversioned, and still reported.
		{"fastmcp", "", confModuleOnly, "unknown"},
		// 0.0.0 is a placeholder, not a version.
		{"agno", "", confModuleOnly, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, ok := by[c.name]
			if !ok {
				t.Fatalf("%s not reported at all; got %v", c.name, keys(by))
			}
			if f.Claim.Version != c.version {
				t.Errorf("version = %q, want %q", f.Claim.Version, c.version)
			}
			if f.Occurrence.Confidence != c.conf {
				t.Errorf("confidence = %v, want %v", f.Occurrence.Confidence, c.conf)
			}
			if !contains(f.Occurrence.Snippet, c.why) {
				t.Errorf("evidence %q does not say how the version was resolved (want %q)", f.Occurrence.Snippet, c.why)
			}
		})
	}
}

// TestPyInstallerDoesNotInventoryEveryPackage is the AIBOM-not-SBOM guard: a
// frozen application bundles hundreds of packages and only the AI ones belong
// in the output.
func TestPyInstallerDoesNotInventoryEveryPackage(t *testing.T) {
	for _, f := range onefile(t) {
		switch f.Claim.Name {
		case "numpy", "click", "certifi":
			t.Errorf("%s reached the AIBOM — the catalog gate is not being applied", f.Claim.Name)
		}
	}
}

// TestPyInstallerEvidenceCitesTheArchive: an unversioned finding must be
// visibly distinguishable from a metadata-confirmed one.
func TestPyInstallerEvidenceCitesTheArchive(t *testing.T) {
	for _, f := range onefile(t) {
		if !contains(f.Occurrence.Snippet, "PyInstaller archive") || !contains(f.Occurrence.Snippet, "modules") {
			t.Errorf("%s evidence = %q, want the archive and its module count", f.Claim.Name, f.Occurrence.Snippet)
		}
		if f.Occurrence.Method != airom.MethodBinary {
			t.Errorf("%s method = %q, want binary-analysis", f.Claim.Name, f.Occurrence.Method)
		}
	}
}

// TestPyInstallerIgnoresOrdinaryExecutables: every binary on a machine reaches
// this detector, and all but a frozen one must cost nothing and say nothing.
func TestPyInstallerIgnoresOrdinaryExecutables(t *testing.T) {
	bin := elfPrefix() // an ELF with no CArchive cookie
	f := detect.NewFile(
		detect.FileRef{Path: "usr/bin/ls", Size: int64(len(bin))},
		bin[:32],
		detect.FileProviders{
			Content:  func() ([]byte, bool, error) { return bin, false, nil },
			ReaderAt: func() (detect.ReaderAtCloser, error) { return nopCloser{bytes.NewReader(bin)}, nil },
		},
	)
	got, err := NewPyInstaller().DetectFile(context.Background(), f)
	if err != nil {
		t.Fatalf("an ordinary executable must not be an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d finding(s) from a non-frozen ELF", len(got))
	}
}

// TestPyInstallerStreamSourceIsAnUnknown: a consume-once source cannot serve
// the EOF cookie. Reporting that beats reporting "no AI".
func TestPyInstallerStreamSourceIsAnUnknown(t *testing.T) {
	bin := elfPrefix()
	f := detect.NewFile(
		detect.FileRef{Path: "opt/app", Size: int64(len(bin))},
		bin[:32],
		detect.FileProviders{Content: func() ([]byte, bool, error) { return bin, false, nil }},
	)
	if _, err := NewPyInstaller().DetectFile(context.Background(), f); err == nil {
		t.Error("a non-seekable source silently reported no AI; want an error the engine can record as an Unknown")
	}
}

func TestScanVersionLiteral(t *testing.T) {
	cases := []struct{ in, want string }{
		{"0.7.8", "0.7.8"},
		{"1.79.0", "1.79.0"},
		{"2.5.3", "2.5.3"},
		{"1.0.0rc1", "1.0.0rc1"},
		{"0.0.0", ""}, // placeholder
		{"3", ""},     // needs two components
		{"not a version", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := scanVersionLiteral(pycWith(c.in)); got != c.want {
			t.Errorf("scanVersionLiteral(pyc %q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func keys(m map[string]detect.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
