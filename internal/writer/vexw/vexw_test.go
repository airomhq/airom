package vexw

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

func inventory(mut ...func(*airom.Inventory)) *airom.Inventory {
	inv := &airom.Inventory{
		Serial:    "urn:uuid:11111111-2222-3333-4444-555555555555",
		Timestamp: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC),
		Tool:      airom.ToolInfo{Name: "airom", Version: "v0.3.5"},
		Components: []airom.Component{
			{
				Kind: airom.KindLibrary, Name: "litellm",
				Version: airom.KnownString("1.79.0"),
				PURL:    "pkg:pypi/litellm@1.79.0",
				Vulnerabilities: []airom.Vulnerability{
					{ID: "CVE-2026-35030", Severity: airom.VulnCritical, Summary: "Auth bypass", Fixed: "1.83.0", Source: "osv.dev", Aliases: []string{"GHSA-jjhc"}},
					{ID: "CVE-2026-49468", Severity: airom.VulnCritical, Summary: "Header injection", Source: "osv.dev", URL: "https://osv.dev/x"},
				},
			},
		},
	}
	for _, m := range mut {
		m(inv)
	}
	return inv
}

func render(t *testing.T, inv *airom.Inventory) document {
	t.Helper()
	var buf bytes.Buffer
	if err := New(writer.Options{}).Write(&buf, inv); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return doc
}

func TestDocumentShape(t *testing.T) {
	doc := render(t, inventory())
	if doc.Context != "https://openvex.dev/ns/v0.2.0" {
		t.Errorf("@context = %q", doc.Context)
	}
	if doc.ID != "urn:uuid:11111111-2222-3333-4444-555555555555" {
		t.Errorf("@id = %q, want the inventory serial reused", doc.ID)
	}
	if doc.Timestamp != "2026-08-03T12:00:00Z" {
		t.Errorf("timestamp = %q", doc.Timestamp)
	}
	// The document version counts revisions of the DOCUMENT. Emitting the
	// tool's version here would be a different claim entirely.
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1 (a fresh scan is revision 1)", doc.Version)
	}
	if !strings.Contains(doc.Tooling, "v0.3.5") {
		t.Errorf("tooling = %q, want the tool version", doc.Tooling)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d, want 2", len(doc.Statements))
	}
}

// TestNeverAssertsNotAffected is the whole point of this writer's design. AIROM
// does no reachability analysis, so a `not_affected` from it would be an
// unfounded all-clear — the one output that could make a consumer stop looking.
func TestNeverAssertsNotAffected(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*airom.Inventory)
	}{
		{"a fix exists upstream", func(i *airom.Inventory) {
			i.Components[0].Vulnerabilities[0].Fixed = "9.9.9"
		}},
		{"low severity", func(i *airom.Inventory) {
			i.Components[0].Vulnerabilities[0].Severity = airom.VulnLow
		}},
		{"unknown severity and no score", func(i *airom.Inventory) {
			i.Components[0].Vulnerabilities[0].Severity = airom.VulnUnknown
			i.Components[0].Vulnerabilities[0].Score = 0
		}},
		{"test-scoped component", func(i *airom.Inventory) {
			i.Components[0].TestOnly = true
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, st := range render(t, inventory(c.mut)).Statements {
				if st.Status != statusAffected {
					t.Errorf("status = %q, want %q — nothing AIROM observes justifies another status",
						st.Status, statusAffected)
				}
			}
		})
	}
}

// TestFixedVersionIsNotAFixedStatus pins the inversion this writer must never
// make. Vulnerability.Fixed names an available UPSTREAM release; VEX `fixed`
// asserts THIS product has remediated the issue. The scanned tree is still
// running the vulnerable version, so mapping one to the other would publish the
// opposite of the truth.
func TestFixedVersionIsNotAFixedStatus(t *testing.T) {
	doc := render(t, inventory())
	var withFix *statement
	for i := range doc.Statements {
		if doc.Statements[i].Vulnerability.Name == "CVE-2026-35030" {
			withFix = &doc.Statements[i]
		}
	}
	if withFix == nil {
		t.Fatal("CVE-2026-35030 missing")
	}
	if withFix.Status == "fixed" {
		t.Fatal("an upstream fixed version became a VEX `fixed` status — that asserts this product is remediated when it is not")
	}
	if withFix.Status != statusAffected {
		t.Errorf("status = %q, want affected", withFix.Status)
	}
	// The upgrade target belongs in the action, which is where it is useful
	// and where it cannot be misread as a remediation claim.
	if !strings.Contains(withFix.ActionStatement, "1.83.0") {
		t.Errorf("action = %q, want the upgrade target", withFix.ActionStatement)
	}
}

// TestActionStatementAlwaysPresent: OpenVEX requires one alongside `affected`,
// including when the advisory names no fix.
func TestActionStatementAlwaysPresent(t *testing.T) {
	for _, st := range render(t, inventory()).Statements {
		if strings.TrimSpace(st.ActionStatement) == "" {
			t.Errorf("%s has no action_statement; OpenVEX requires one with `affected`", st.Vulnerability.Name)
		}
	}
	// The no-fix branch should say so rather than inventing a target.
	doc := render(t, inventory())
	for _, st := range doc.Statements {
		if st.Vulnerability.Name == "CVE-2026-49468" && !strings.Contains(st.ActionStatement, "No fixed version") {
			t.Errorf("no-fix action = %q, want it to say no fix is named", st.ActionStatement)
		}
	}
}

// TestOnlyPurlBearingComponents: a statement's product must be something a
// consumer can match against. A hosted model or a prompt has no purl by design.
func TestOnlyPurlBearingComponents(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) {
		i.Components = append(i.Components, airom.Component{
			Kind: airom.KindHostedLLM, Name: "gpt-4o", // no PURL by design (D9)
			Vulnerabilities: []airom.Vulnerability{{ID: "CVE-9999-1", Source: "osv.dev"}},
		})
	})
	for _, st := range render(t, inv).Statements {
		if st.Vulnerability.Name == "CVE-9999-1" {
			t.Error("emitted a statement for a component with no purl; nothing could match its product")
		}
		if st.Products[0].ID == "" {
			t.Error("statement with an empty product id")
		}
	}
}

func TestCleanInventoryIsAnEmptyStatementList(t *testing.T) {
	inv := inventory(func(i *airom.Inventory) { i.Components[0].Vulnerabilities = nil })
	var buf bytes.Buffer
	if err := New(writer.Options{}).Write(&buf, inv); err != nil {
		t.Fatal(err)
	}
	// `[]`, not null: a consumer parsing the document should see "no
	// statements", not a missing field it has to special-case.
	if !bytes.Contains(buf.Bytes(), []byte(`"statements": []`)) {
		t.Errorf("clean scan should emit an empty array, got:\n%s", buf.String())
	}
}

// TestDeterministic: two renders of one inventory must be byte-identical (P7),
// and statement order must not depend on map iteration anywhere upstream.
func TestDeterministic(t *testing.T) {
	inv := inventory()
	var first bytes.Buffer
	if err := New(writer.Options{}).Write(&first, inv); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		var next bytes.Buffer
		if err := New(writer.Options{}).Write(&next, inv); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), next.Bytes()) {
			t.Fatalf("render %d differs from the first", i+1)
		}
	}
}

func TestRegisteredWithTheWriterRegistry(t *testing.T) {
	w, err := writer.New("vex", writer.Options{})
	if err != nil {
		t.Fatalf("vex not registered: %v", err)
	}
	if w.Format() != "vex" {
		t.Errorf("Format() = %q", w.Format())
	}
}
