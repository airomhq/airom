// Package e2e is the end-to-end golden suite: it drives the whole scanner —
// walk, classify, dispatch, the built-in detectors, the embedded rule packs,
// assembly — through the app.Scan seam over committed fixture repositories,
// then renders every writer format and locks the bytes down as goldens.
//
// The embedded rule packs are active by default (app's init sets
// app.EmbeddedRules), so the fixtures exercise the real detector + rule
// surface, not a stub. Goldens are portable: machine-specific values (the
// random serial, the wall clock, and the absolute scan target) are normalized
// away BEFORE rendering, and every writer is a deterministic pure projection
// of the assembled graph (invariants P5, P7).
//
// Regenerate goldens after an intended behavior change:
//
//	go test ./internal/e2e/... -update
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/app"
	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"

	// Register every writer format via its init().
	_ "github.com/airomhq/airom/internal/writer/cdx"
	_ "github.com/airomhq/airom/internal/writer/nativejson"
	_ "github.com/airomhq/airom/internal/writer/sarifw"
	_ "github.com/airomhq/airom/internal/writer/tablew"
	_ "github.com/airomhq/airom/internal/writer/yamlw"
)

// update regenerates the golden files instead of comparing against them.
var update = flag.Bool("update", false, "regenerate golden files")

// Injected clock and serial: the two values a real scan draws from the
// environment (time.Now, crypto/rand). Pinning them is what makes the goldens
// reproducible (P7).
//
// The day matters beyond reproducibility: the EOL overlay evaluates retirement
// dates against it, so it is pinned AFTER the lifecycle catalog's `verified`
// date. A scan day earlier than that would mean the catalog knows things the
// scan date does not — an inconsistency the overlay reports rather than hides.
var fixedTimestamp = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

const fixedSerial = "urn:uuid:00000000-0000-4000-8000-000000000000"

// goldenFormats pairs each writer format with its golden filename.
var goldenFormats = []struct{ format, file string }{
	{"json", "aibom.json"},
	{"cyclonedx", "bom.cdx.json"},
	{"sarif", "scan.sarif"},
	{"yaml", "aibom.yaml"},
	{"table", "table.txt"},
	{"vex", "openvex.json"},
	{"spdx", "bom.spdx.json"},
}

// goldenFixtures are the repositories golden-filed across every format.
var goldenFixtures = []string{
	"python-langchain-rag",
	"node-openai",
	"go-openai",
	"mixed-monorepo",
	"risky-models",
	// Pinned to models across every lifecycle state, so the EOL overlay's
	// projection is golden-filed rather than merely unit-tested.
	"eol-models",
	// Production code, a tests/ tree, and a testdata/ tree naming different
	// models — plus one model named in BOTH app.py and the suite, which must
	// stay a real component. Golden-files the test-scope split across every
	// format, including CycloneDX `scope: excluded`.
	"test-scoped",
	// A deployed environment: shipped code and a site-packages tree, with no
	// manifest anywhere. Golden-files the one input where AIROM can report
	// exact installed versions rather than declared ranges — and pins the two
	// guards that keep it an AIBOM: the AI catalog (numpy stays out) and the
	// .dist-info/.egg-info parent check (a stray docs/METADATA stays out).
	"installed-env",
	// Manifests and lockfiles side by side, so the version story is pinned in
	// one table: openai resolves to 4.28.4 from the npm lockfile despite the
	// manifest saying ^4.20.0, anthropic resolves from poetry.lock, and
	// @langchain/core — declared but never locked — keeps its range instead of
	// being reported as the release at its lower bound.
	"locked-deps",
	// agno, crawl4ai, and fastmcp declared AND used. Pins two things that are
	// easy to regress independently: each framework folds into ONE component
	// carrying both the manifest version and the code sightings (an empty
	// catalog provider silently splits it in two), and `from agnostic import`
	// is not claimed as agno.
	"agentic-stack",
}

func fixtureDir(name string) string { return filepath.Join("testdata", "fixtures", name) }

// scanNormalized runs the full pipeline over a fixture and normalizes the
// assembled inventory so it is byte-portable. tweak may adjust the Config
// (e.g. Parallel) before the scan; it may be nil.
func scanNormalized(t *testing.T, name string, tweak func(*app.Config)) *airom.Inventory {
	t.Helper()
	cfg := &app.Config{
		Source: app.SourceFS,
		Target: fixtureDir(name),
		// Isolate the rule cache: a scan resolves its base rule layer from
		// CacheDir (a fetched bundle overrides the embedded packs), and
		// ApplyDefaults would otherwise point it at the real user cache —
		// making the goldens depend on whether a dev ran `airom rules update`.
		// An empty temp dir has no bundle, so the scan uses the embedded packs.
		CacheDir: t.TempDir(),
		// The goldens are committed INSIDE the fixture tree
		// (fixtures/<name>/golden/), so the scan must never walk them —
		// otherwise the suite is non-idempotent (each written golden becomes
		// an extra walked file on the next run). Excluding it keeps every
		// scan a pure function of the source files.
		IgnoreGlobs: []string{"**/golden", "**/golden/**"},
		// Pin the scan clock for the same reason CacheDir is isolated above: the
		// EOL overlay answers "has this model's shutdown date arrived yet?", so
		// on a wall clock a golden would silently change the day a curated
		// retirement passes. With the day fixed, the scan stays a pure function
		// of the fixture bytes.
		Now: fixedTimestamp,
	}
	if tweak != nil {
		tweak(cfg)
	}
	inv, err := app.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("scan %s: %v", name, err)
	}
	normalize(inv, name)
	return inv
}

// normalize strips every machine-specific and volatile value from an
// inventory while keeping the stable honesty counters. It runs BEFORE
// rendering so the goldens never carry a machine path, a wall clock, a random
// serial, or a timing measurement. The root component's identity already
// derives from the fixture-name basename, so overwriting Source.Target with
// the bare name keeps it consistent with the minted root.
func normalize(inv *airom.Inventory, name string) {
	inv.Serial = fixedSerial
	inv.Timestamp = fixedTimestamp
	inv.Source.Target = name

	// Duration and per-detector nanoseconds are legitimately nondeterministic
	// (§14); zero them. FilesWalked/Processed/Failed, the byte counters, the
	// selection explanation, and the detector invocation/finding counts are
	// all stable functions of the fixed fixture bytes, so they stay.
	inv.Stats.Duration = 0
	for i := range inv.Stats.Detectors {
		inv.Stats.Detectors[i].NS = 0
	}

	// The rule-pack hash is deterministic for a fixed ruleset but changes
	// whenever any embedded rule changes — pinning the real value here would
	// force every e2e golden to be regenerated on rule edits that don't even
	// touch these fixtures. Normalize it; the exact projection is asserted in
	// the writer unit tests (writertest fixture carries a fixed hash).
	// RulesVersion ("builtin") is stable, so it stays.
	if inv.Tool.RulesHash != "" {
		inv.Tool.RulesHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}
}

// renderFormat renders inv to one writer format with default options.
func renderFormat(t *testing.T, format string, inv *airom.Inventory) []byte {
	t.Helper()
	w, err := writer.New(format, writer.Options{})
	if err != nil {
		t.Fatalf("writer.New(%q): %v", format, err)
	}
	var buf bytes.Buffer
	if err := w.Write(&buf, inv); err != nil {
		t.Fatalf("write %s: %v", format, err)
	}
	return buf.Bytes()
}

// checkGolden compares got against the golden at path, or rewrites it under
// -update.
func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update || os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run `go test ./internal/e2e/... -update` to create it)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s\n%s", path, firstLineDiff(got, want))
	}
}

// TestGoldenFixtures scans every fixture and byte-compares every rendered
// format against its committed golden — the core end-to-end contract.
func TestGoldenFixtures(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			inv := scanNormalized(t, name, nil)
			for _, gf := range goldenFormats {
				got := renderFormat(t, gf.format, inv)
				golden := filepath.Join(fixtureDir(name), "golden", gf.file)
				checkGolden(t, golden, got)
			}
		})
	}
}

// TestScanDeterminismParallelism proves invariant P7 end-to-end: the assembled
// output is independent of worker count. Two scans of the same fixture at
// Parallel=1 and Parallel=16 must render byte-identical native JSON.
func TestScanDeterminismParallelism(t *testing.T) {
	const fixture = "python-langchain-rag"
	inv1 := scanNormalized(t, fixture, func(c *app.Config) { c.Parallel = 1 })
	inv16 := scanNormalized(t, fixture, func(c *app.Config) { c.Parallel = 16 })

	j1 := renderFormat(t, "json", inv1)
	j16 := renderFormat(t, "json", inv16)
	if !bytes.Equal(j1, j16) {
		t.Errorf("P7 violated: Parallel=1 and Parallel=16 produced different output\n%s", firstLineDiff(j16, j1))
	}
}

// TestScanChaosDegradation proves per-file degradation end-to-end (invariant
// P6): a tree of deliberately corrupt weight files must not crash the scan.
// The truncated PyTorch zip surfaces as an attributed Unknown; the malformed
// safetensors/onnx/gguf degrade silently; and the valid components sitting
// beside them are still discovered.
func TestScanChaosDegradation(t *testing.T) {
	inv := scanNormalized(t, "malformed-models", nil)
	// Reaching here already proves the scan COMPLETED without error.

	// The corrupt torch zip must degrade to an attributed Unknown, not a panic.
	var torch *airom.Unknown
	for i := range inv.Unknowns {
		if inv.Unknowns[i].DetectorID == "modelfilex/torch" {
			torch = &inv.Unknowns[i]
			break
		}
	}
	if torch == nil {
		t.Fatalf("expected a modelfilex/torch Unknown for the corrupt broken.pt; unknowns = %+v", inv.Unknowns)
	}
	if !strings.Contains(torch.Path, "broken.pt") {
		t.Errorf("torch Unknown path = %q, want it to name broken.pt", torch.Path)
	}
	if strings.TrimSpace(torch.Reason) == "" {
		t.Errorf("torch Unknown carries no reason")
	}

	// The degradation is accounted honestly in the stats block.
	if inv.Stats.FilesFailed < 1 {
		t.Errorf("Stats.FilesFailed = %d, want >= 1 (the corrupt torch file)", inv.Stats.FilesFailed)
	}

	// Valid components in the same tree are still found: the well-formed GGUF
	// weight file and the langchain manifest entry.
	names := componentNames(inv)
	for _, want := range []string{"tiny.gguf", "langchain"} {
		if !names[want] {
			t.Errorf("valid component %q was dropped; found: %v", want, sortedKeys(names))
		}
	}

	// The malformed safetensors/onnx must not have produced phantom
	// components — they degrade to nothing, honestly.
	for _, ghost := range []string{"corrupt.safetensors", "garbage.onnx"} {
		if names[ghost] {
			t.Errorf("malformed file %q produced a phantom component", ghost)
		}
	}
}

// TestCrossFormatConsistency proves the writers are consistent projections of
// one graph: the native-JSON component set equals the CycloneDX component set,
// modulo the application root that CDX relocates into metadata.component.
func TestCrossFormatConsistency(t *testing.T) {
	inv := scanNormalized(t, "python-langchain-rag", nil)

	nativeNames := multiset(componentNamesSlice(inv))

	cdxBytes := renderFormat(t, "cyclonedx", inv)
	var cdxDoc struct {
		Metadata struct {
			Component struct {
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
	}
	if err := json.Unmarshal(cdxBytes, &cdxDoc); err != nil {
		t.Fatalf("parse cdx: %v", err)
	}

	cdxNames := []string{cdxDoc.Metadata.Component.Name} // the root lives here
	for _, c := range cdxDoc.Components {
		cdxNames = append(cdxNames, c.Name)
	}

	if got, want := len(cdxNames), len(inv.Components); got != want {
		t.Errorf("component count: cdx has %d (incl. metadata root), native has %d", got, want)
	}
	if diff := multisetDiff(nativeNames, multiset(cdxNames)); diff != "" {
		t.Errorf("component-name sets diverge between native json and cyclonedx:\n%s", diff)
	}
}

// TestSPDXGraphIsClosed proves on real scans what the writer's unit tests prove
// on synthetic ones: every IRI an SPDX element points at is an element the
// document actually declares. A dangling reference is invisible by eye and
// invisible to a byte-comparison golden — the document stays well-formed JSON
// and every field looks plausible — but it is an invalid SPDX graph, and the
// first draft of this writer shipped exactly that (Agent IRIs minted for
// suppliers, no Agent elements emitted).
//
// It also checks the direction that the CycloneDX cross-format test cannot:
// CDX hoists the scan root out of components[] into metadata.component, while
// SPDX's software_Sbom.rootElement is a REFERENCE, so the root must remain a
// graph element here.
func TestSPDXGraphIsClosed(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			inv := scanNormalized(t, name, nil)

			var doc struct {
				Graph []map[string]any `json:"@graph"`
			}
			if err := json.Unmarshal(renderFormat(t, "spdx", inv), &doc); err != nil {
				t.Fatalf("parse spdx: %v", err)
			}

			declared := make(map[string]bool, len(doc.Graph))
			pkgNames := []string{}
			for _, e := range doc.Graph {
				for _, key := range []string{"spdxId", "@id"} {
					if id, ok := e[key].(string); ok {
						declared[id] = true
					}
				}
				switch e["type"] {
				case "software_Package", "ai_AIPackage", "dataset_DatasetPackage":
					n, _ := e["name"].(string)
					pkgNames = append(pkgNames, n)
				}
			}

			// Every component becomes exactly one package element — including
			// the root, unlike CycloneDX.
			if diff := multisetDiff(multiset(componentNamesSlice(inv)), multiset(pkgNames)); diff != "" {
				t.Errorf("component-name sets diverge between native json and spdx:\n%s", diff)
			}

			const noAssertionElement = "https://spdx.org/rdf/3.0.1/terms/Core/NoAssertionElement"
			refFields := []string{
				"suppliedBy", "originatedBy", "from", "to",
				"createdBy", "createdUsing", "creationInfo", "rootElement", "element",
			}
			for _, e := range doc.Graph {
				for _, f := range refFields {
					for _, ref := range spdxRefs(e[f]) {
						if ref == noAssertionElement {
							continue // a defined SPDX individual, not a document element
						}
						if !declared[ref] {
							t.Errorf("%v.%s → %q, which is not declared in @graph", e["spdxId"], f, ref)
						}
					}
				}
			}
		})
	}
}

// spdxRefs flattens a field that may hold one IRI or a list of them.
func spdxRefs(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ── small helpers ───────────────────────────────────────────────────────────

func componentNames(inv *airom.Inventory) map[string]bool {
	m := make(map[string]bool, len(inv.Components))
	for _, c := range inv.Components {
		m[c.Name] = true
	}
	return m
}

func componentNamesSlice(inv *airom.Inventory) []string {
	out := make([]string, 0, len(inv.Components))
	for _, c := range inv.Components {
		out = append(out, c.Name)
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// multiset counts occurrences of each string (names need not be unique).
func multiset(xs []string) map[string]int {
	m := make(map[string]int, len(xs))
	for _, x := range xs {
		m[x]++
	}
	return m
}

// multisetDiff returns a human-readable description of the symmetric
// difference between two multisets, or "" when they are equal.
func multisetDiff(a, b map[string]int) string {
	keys := map[string]struct{}{}
	for k := range a {
		keys[k] = struct{}{}
	}
	for k := range b {
		keys[k] = struct{}{}
	}
	var lines []string
	for k := range keys {
		if a[k] != b[k] {
			lines = append(lines, k+": native="+itoa(a[k])+" cdx="+itoa(b[k]))
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// firstLineDiff reports the first line at which got and want differ, with a
// little context — far more useful than dumping two large documents.
func firstLineDiff(got, want []byte) string {
	gl := strings.Split(string(got), "\n")
	wl := strings.Split(string(want), "\n")
	n := len(gl)
	if len(wl) < n {
		n = len(wl)
	}
	for i := 0; i < n; i++ {
		if gl[i] != wl[i] {
			return "first difference at line " + itoa(i+1) + ":\n  got:  " + gl[i] + "\n  want: " + wl[i]
		}
	}
	if len(gl) != len(wl) {
		return "documents share a prefix but differ in length: got " +
			itoa(len(gl)) + " lines, want " + itoa(len(wl)) + " lines"
	}
	return "documents differ in trailing bytes but not by line"
}
