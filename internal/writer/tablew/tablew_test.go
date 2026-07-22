package tablew_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/internal/writer/tablew"
	"github.com/airomhq/airom/internal/writer/writertest"
	"github.com/airomhq/airom/pkg/airom"
)

func render(t *testing.T, opts writer.Options, inv *airom.Inventory) string {
	t.Helper()
	w, err := writer.New("table", opts)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := w.Write(&buf, inv); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestTable(t *testing.T) {
	inv := writertest.BuildFixture()
	out := render(t, writer.Options{}, inv)
	// the app root is metadata, never a table row
	if strings.Contains(out, "ai-app") && strings.Contains(out, "application") {
		t.Error("scan-root application must not appear as a component row")
	}
	for _, want := range []string{
		"gpt-4.1", "langchain", "0.2.1", "hosted-llm",
		"Scan Summary", "Components", "By Type", "By Severity",
		// the fixture's tiny.gguf carries a high pickle-import risk
		"high", "pickle-import",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	// deterministic
	if render(t, writer.Options{}, inv) != out {
		t.Error("table not deterministic")
	}
}

func TestTableWide(t *testing.T) {
	inv := writertest.BuildFixture()
	out := render(t, writer.Options{TableWide: true}, inv)
	if !strings.Contains(out, "src/rag.py:7") || !strings.Contains(out, "rules/openai/model-literal") {
		t.Errorf("wide table missing occurrence detail:\n%s", out)
	}
}

func TestTableEmpty(t *testing.T) {
	inv := &airom.Inventory{Source: airom.SourceInfo{Target: "/empty"}}
	if out := render(t, writer.Options{}, inv); !strings.Contains(out, "No AI components found") {
		t.Errorf("empty table = %q", out)
	}
}

var _ = tablew.Writer{}
