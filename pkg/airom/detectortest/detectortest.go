// Package detectortest is the public contract-test harness for AIROM
// detectors (ARCHITECTURE.md §14, plugin-guide.md B.4): built-in and
// third-party detectors prove themselves with the identical harness. It
// asserts golden findings, real-index selector gating, location
// conventions, determinism, robustness against truncated inputs, and
// source-agnosticism (dir-backed AND stream-backed runs).
package detectortest

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

var update = flag.Bool("update", false, "rewrite detectortest golden files")

// Fixtures configures a harness run.
type Fixtures struct {
	// Dir holds the fixture files and findings.golden.json.
	Dir string
	// Golden overrides the golden filename (default "findings.golden.json").
	Golden string
}

// headerSize mirrors the engine's shared header sample length.
const headerSize = 32 * 1024

// Run executes the full detector contract (plugin-guide.md B.4):
//
//  1. golden findings match (regenerate with -update or UPDATE_GOLDEN=1)
//  2. Selector() actually gates, through the real compiled dispatch index
//  3. locations are 1-based (0 = whole-file)
//  4. determinism: two runs produce identical findings
//  5. no panic on truncated/empty inputs
//  6. both backings: dir-backed (ReaderAt works) and stream-backed
//     (ReaderAt returns ErrNotSeekable) produce identical findings
func Run(t *testing.T, det detect.Detector, fx Fixtures) {
	t.Helper()

	fd, ok := det.(detect.FileDetector)
	if !ok {
		t.Fatalf("detectortest: %T is not a FileDetector (project-detector harness support lands with the first project detector)", det)
	}
	if det.ID() == "" {
		t.Fatal("contract: detector ID must be non-empty")
	}
	if det.Version() < 1 {
		t.Fatalf("contract: detector Version() = %d, want >= 1", det.Version())
	}

	index, err := detect.NewIndex([]detect.Detector{det})
	if err != nil {
		t.Fatalf("contract: selector does not compile: %v", err)
	}

	fixtures := listFixtures(t, fx)
	if len(fixtures) == 0 {
		t.Fatalf("no fixtures under %s", fx.Dir)
	}

	golden := map[string][]detect.Finding{}
	matchedAny := false

	for _, backing := range []string{"dir", "stream"} {
		perBacking := map[string][]detect.Finding{}
		for _, name := range fixtures {
			data, ref := loadFixture(t, fx.Dir, name)
			header := data
			if len(header) > headerSize {
				header = header[:headerSize]
			}

			if len(index.Match(ref, header)) == 0 {
				continue // selector gates it away — DetectFile must never see it
			}
			matchedAny = true

			run := func() []detect.Finding {
				f := makeFile(t, fx.Dir, name, ref, data, backing)
				findings := invoke(t, fd, f, name, backing)
				assertContract(t, findings, name)
				return canonicalize(findings)
			}
			first := run()
			second := run()
			if !reflect.DeepEqual(first, second) {
				t.Errorf("contract: %s (%s backing): two runs differ — detector is nondeterministic (P7)", name, backing)
			}
			perBacking[name] = first

			// Robustness: truncated variants must error or return findings,
			// never panic (§13: parsers eat untrusted bytes).
			for _, variant := range truncations(data) {
				vref := ref
				vref.Size = int64(len(variant.data))
				vf := makeStreamFile(vref, variant.data)
				func() {
					defer func() {
						if p := recover(); p != nil {
							t.Errorf("contract: %s: panic on %s input: %v", name, variant.name, p)
						}
					}()
					_, _ = fd.DetectFile(context.Background(), vf)
				}()
			}
		}

		if backing == "dir" {
			golden = perBacking
		} else if !reflect.DeepEqual(golden, perBacking) {
			t.Errorf("contract: dir-backed and stream-backed findings differ — the detector depends on seekability (use Content(), not ReaderAt, for parsing; ReaderAt is unavailable on image scans)")
		}
	}

	if !matchedAny {
		t.Fatalf("contract: the selector matched no fixture — add a positive fixture or fix Selector()")
	}

	compareGolden(t, fx, golden)
}

func listFixtures(t *testing.T, fx Fixtures) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(fx.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasSuffix(p, ".golden.json") {
			return nil
		}
		rel, err := filepath.Rel(fx.Dir, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	sort.Strings(out)
	return out
}

func loadFixture(t *testing.T, dir, name string) ([]byte, detect.FileRef) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	data, err := os.ReadFile(p) // #nosec G304 -- reads the caller's own fixture dir
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data, detect.FileRef{
		Path:     name,
		Size:     int64(len(data)),
		Language: detect.LanguageOf(name),
	}
}

func makeFile(t *testing.T, dir, name string, ref detect.FileRef, data []byte, backing string) *detect.File {
	t.Helper()
	if backing == "stream" {
		return makeStreamFile(ref, data)
	}
	abs := filepath.Join(dir, filepath.FromSlash(name))
	header := data
	if len(header) > headerSize {
		header = header[:headerSize]
	}
	return detect.NewFile(ref, header, detect.FileProviders{
		Content: func() ([]byte, bool, error) { return data, false, nil },
		ReaderAt: func() (detect.ReaderAtCloser, error) {
			return os.Open(abs) // #nosec G304 -- caller's own fixture dir; *os.File is ReaderAt+Closer
		},
	})
}

// makeStreamFile mimics a tar-stream source: one-shot content, no ReaderAt.
func makeStreamFile(ref detect.FileRef, data []byte) *detect.File {
	header := data
	if len(header) > headerSize {
		header = header[:headerSize]
	}
	return detect.NewFile(ref, header, detect.FileProviders{
		Content: func() ([]byte, bool, error) { return data, false, nil },
		// ReaderAt deliberately nil → detect.ErrNotSeekable.
	})
}

func invoke(t *testing.T, fd detect.FileDetector, f *detect.File, name, backing string) []detect.Finding {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("contract: %s (%s backing): DetectFile panicked: %v (the engine would degrade this to an Unknown, but the harness treats panics as failures — fix it here)", name, backing, p)
		}
	}()
	findings, err := fd.DetectFile(context.Background(), f)
	if err != nil {
		t.Fatalf("%s (%s backing): DetectFile error: %v", name, backing, err)
	}
	return findings
}

func assertContract(t *testing.T, findings []detect.Finding, name string) {
	t.Helper()
	for i, f := range findings {
		if f.Claim.Name == "" {
			t.Errorf("contract: %s finding[%d]: empty Claim.Name", name, i)
		}
		if f.Claim.Kind == "" {
			t.Errorf("contract: %s finding[%d]: empty Claim.Kind", name, i)
		}
		loc := f.Occurrence.Location
		if loc.Line < 0 || loc.Column < 0 || loc.EndLine < 0 || loc.EndColumn < 0 {
			t.Errorf("contract: %s finding[%d]: negative location (%+v); lines/columns are 1-based, 0 = whole-file (D18)", name, i, loc)
		}
		if loc.EndLine > 0 && loc.EndLine < loc.Line {
			t.Errorf("contract: %s finding[%d]: EndLine %d < Line %d", name, i, loc.EndLine, loc.Line)
		}
		if c := f.Occurrence.Confidence; c <= 0 || c > 1 {
			t.Errorf("contract: %s finding[%d]: confidence %v outside (0, 1]", name, i, c)
		}
	}
}

type truncation struct {
	name string
	data []byte
}

func truncations(data []byte) []truncation {
	out := []truncation{{"empty", nil}}
	if len(data) > 0 {
		out = append(out, truncation{"1-byte", data[:1]})
	}
	if len(data) > 64 {
		out = append(out, truncation{"header-truncated", data[:64]})
	}
	return out
}

// canonicalize normalizes finding order and fills the detector-attribution
// fields the dispatcher would fill, so goldens match engine behavior.
func canonicalize(findings []detect.Finding) []detect.Finding {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i].Occurrence, findings[j].Occurrence
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.DetectorID != b.DetectorID {
			return a.DetectorID < b.DetectorID
		}
		return findings[i].Claim.Name < findings[j].Claim.Name
	})
	return findings
}

func compareGolden(t *testing.T, fx Fixtures, got map[string][]detect.Finding) {
	t.Helper()
	goldenName := fx.Golden
	if goldenName == "" {
		goldenName = "findings.golden.json"
	}
	goldenPath := filepath.Join(fx.Dir, goldenName)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(got); err != nil {
		t.Fatalf("marshal findings: %v", err)
	}

	if *update || os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(goldenPath, buf.Bytes(), 0o644); err != nil { // #nosec G306 -- goldens are source files, world-readable like any checked-in test data
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("golden updated: %s", goldenPath)
		return
	}

	want, err := os.ReadFile(goldenPath) // #nosec G304 -- caller's own fixture dir
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to create it)", goldenPath, err)
	}
	if !bytes.Equal(normalizeNL(want), normalizeNL(buf.Bytes())) {
		t.Errorf("findings differ from %s (run with -update after reviewing):\n--- got ---\n%s", goldenPath, truncateForLog(buf.String()))
	}
}

func normalizeNL(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }

func truncateForLog(s string) string {
	if len(s) > 4000 {
		return s[:4000] + "\n… (truncated)"
	}
	return s
}
