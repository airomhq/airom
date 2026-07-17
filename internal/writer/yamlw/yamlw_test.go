package yamlw_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Roro1727/airom/internal/writer/writertest"
	"github.com/Roro1727/airom/internal/writer/yamlw"
	"github.com/Roro1727/airom/pkg/airom"
)

var update = flag.Bool("update", false, "update golden files")

func TestGoldenAndDeterminism(t *testing.T) {
	inv := writertest.BuildFixture()
	var a, b bytes.Buffer
	if err := (yamlw.Writer{}).Write(&a, inv); err != nil {
		t.Fatal(err)
	}
	_ = (yamlw.Writer{}).Write(&b, inv)
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("yaml not deterministic (P7)")
	}
	golden := filepath.Join("testdata", "inventory.golden.yaml")
	if *update || os.Getenv("UPDATE_GOLDEN") != "" {
		_ = os.MkdirAll("testdata", 0o750)
		if err := os.WriteFile(golden, a.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run -update): %v", err)
	}
	if !bytes.Equal(want, a.Bytes()) {
		t.Error("yaml differs from golden")
	}
}

// TestLargeInt64RendersAsInteger locks the fix for the int64→scientific-notation
// bug: large model int64 fields (ParamCount, SizeBytes) must render as plain
// integers, byte-aligned with native JSON, never as floats like 8.03e+09.
// (Phase 10 review, writers-conformance finding.)
func TestLargeInt64RendersAsInteger(t *testing.T) {
	inv := &airom.Inventory{
		Components: []airom.Component{{
			ID:   "airom:test",
			Kind: airom.KindLocalModelFile,
			Name: "llama",
			Model: &airom.ModelFacet{
				ParamCount:    airom.KnownInt64(8030261248),
				ContextLength: airom.KnownInt64(1000000),
			},
			Data: &airom.DataFacet{SizeBytes: airom.KnownInt64(123456789012)},
		}},
	}
	var buf bytes.Buffer
	if err := (yamlw.Writer{}).Write(&buf, inv); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"paramCount: 8030261248", "contextLength: 1000000", "sizeBytes: 123456789012"} {
		if !strings.Contains(out, want) {
			t.Errorf("YAML missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "e+") || strings.Contains(out, "E+") {
		t.Errorf("YAML rendered an int64 in scientific notation:\n%s", out)
	}
}
