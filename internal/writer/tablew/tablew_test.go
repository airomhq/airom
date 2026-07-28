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
		"Scan Summary", "Components", "By Type",
		// the fixture's langchain carries one high CVE — the summary shows a
		// Vulnerabilities breakdown and the component table a VULN column
		"Vulnerabilities", "total", "VULN", "high (1)",
		// the per-CVE detail table follows the component table
		"LIBRARY", "VULNERABILITY", "SEVERITY", "STATUS", "INSTALLED", "FIXED", "TITLE",
		"CVE-2024-0001", "HIGH", "fixed", "0.2.5",
		"Server-side request forgery", "https://osv.dev/vulnerability/CVE-2024-0001",
		// the fixture's gpt-4.1 is deprecated with 98 days left — the EOL column
		// shows the deadline (the number that decides urgency), and the detail
		// table names the migration target plus ITS state
		"EOL", "98d", "Model lifecycle", "MIGRATE TO", "gpt-4.2 (deprecated)",
		"2026-10-23", "example.com/deprecations", "verified 2026-07-17",
		// the LOCATION column shows each component's primary sighting —
		// gpt-4.1 has two occurrences, so this also asserts the min-pick
		"LOCATION", "src/rag.py:7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	// the RISK/FLAGS columns and their risk slugs are gone from the table view
	for _, gone := range []string{"RISK", "FLAGS", "pickle-import"} {
		if strings.Contains(out, gone) {
			t.Errorf("table should no longer surface %q:\n%s", gone, out)
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
