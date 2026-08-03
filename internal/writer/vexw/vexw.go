// Package vexw writes an OpenVEX document from the CVE overlay.
//
// VEX answers a narrower question than a BOM: for a known vulnerability in a
// component you ship, are you actually affected? The value of that is almost
// entirely in the negative direction — a supplier saying "we ship this
// component but the vulnerable path is unreachable" is what saves a consumer
// from chasing it.
//
// AIROM cannot say that, and this writer never does. It performs no
// reachability analysis: it knows a component is present at a version an
// advisory database lists as vulnerable, and nothing more. So every statement
// it emits is `affected`, and `not_affected` is unreachable by construction —
// see statusFor. A document asserting otherwise would be worse than no
// document, because a consumer would stop looking.
package vexw

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

func init() {
	writer.Register(format, func(o writer.Options) writer.Writer { return New(o) })
}

const (
	format = "vex"

	// context is the OpenVEX spec version this document conforms to.
	context = "https://openvex.dev/ns/v0.2.0"

	// statusAffected is the only status this writer emits. OpenVEX also
	// defines not_affected, fixed, and under_investigation:
	//
	//   not_affected  needs a justification that the vulnerable code cannot be
	//                 reached. AIROM does no reachability analysis, so it has
	//                 no grounds for one.
	//   fixed         asserts THIS product has remediated the vulnerability.
	//                 Tempting to map from Vulnerability.Fixed, which is the
	//                 opposite claim — that an upstream release exists while
	//                 the scanned tree still runs the vulnerable version. That
	//                 mapping would invert the meaning, so Fixed goes into the
	//                 action statement instead.
	//   under_investigation
	//                 a human's assertion about work in progress, not
	//                 something a scanner can know.
	statusAffected = "affected"
)

// Writer renders an Inventory as OpenVEX.
type Writer struct{ opts writer.Options }

// New constructs the VEX writer.
func New(o writer.Options) Writer { return Writer{opts: o} }

// Format implements writer.Writer.
func (Writer) Format() string { return format }

// ── OpenVEX wire types (v0.2.0) ────────────────────────────────────────────

type document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Tooling    string      `json:"tooling,omitempty"`
	Statements []statement `json:"statements"`
}

type statement struct {
	Vulnerability   vulnerability `json:"vulnerability"`
	Timestamp       string        `json:"timestamp,omitempty"`
	Products        []product     `json:"products"`
	Status          string        `json:"status"`
	ActionStatement string        `json:"action_statement,omitempty"`
}

type vulnerability struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

type product struct {
	ID string `json:"@id"`
}

// Write emits the document.
func (wr Writer) Write(w io.Writer, inv *airom.Inventory) error {
	doc := document{
		Context:   context,
		ID:        vexID(inv),
		Author:    author(inv),
		Timestamp: inv.Timestamp.UTC().Format(time.RFC3339),
		// A VEX document's version counts REVISIONS of that document, not the
		// tool's version. A fresh scan is always revision 1; amending a
		// previous statement is the consumer's workflow, not a scanner's.
		Version:    1,
		Tooling:    tooling(inv),
		Statements: statements(inv),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// statements builds one statement per (component, vulnerability), sorted so the
// document is byte-identical for an unchanged scan (P7).
func statements(inv *airom.Inventory) []statement {
	out := []statement{}
	for i := range inv.Components {
		c := &inv.Components[i]
		// A product has to be identifiable to a consumer, and in VEX that
		// means a purl. A component without one — a hosted model, a prompt —
		// cannot be the subject of a statement anybody could match against.
		if c.PURL == "" || len(c.Vulnerabilities) == 0 {
			continue
		}
		for _, v := range c.Vulnerabilities {
			out = append(out, statement{
				Vulnerability: vulnerability{
					Name:        v.ID,
					Description: v.Summary,
					Aliases:     v.Aliases,
				},
				Timestamp:       inv.Timestamp.UTC().Format(time.RFC3339),
				Products:        []product{{ID: c.PURL}},
				Status:          statusFor(v),
				ActionStatement: actionFor(c, v),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Products[0].ID != out[j].Products[0].ID {
			return out[i].Products[0].ID < out[j].Products[0].ID
		}
		return out[i].Vulnerability.Name < out[j].Vulnerability.Name
	})
	return out
}

// statusFor is deliberately total: every vulnerability AIROM found is one it
// observed present at a vulnerable version, and it has done nothing that could
// justify any other status. Kept as a function rather than a constant so the
// reason lives next to the decision, and so adding reachability analysis later
// has an obvious place to change.
func statusFor(airom.Vulnerability) string { return statusAffected }

// actionFor states what a consumer should do. OpenVEX requires an
// action_statement alongside `affected`, and the upgrade target is the useful
// thing to put there — it is also where Vulnerability.Fixed belongs, since it
// describes an available upstream release rather than a remediation this
// product has made.
func actionFor(c *airom.Component, v airom.Vulnerability) string {
	name := c.Name
	if installed, ok := c.Version.Value(); ok && installed != "" {
		name = fmt.Sprintf("%s %s", name, installed)
	}
	if v.Fixed != "" {
		return fmt.Sprintf("Upgrade %s to %s or later.", name, v.Fixed)
	}
	return fmt.Sprintf(
		"No fixed version is named by the advisory for %s; consult %s.",
		name, orDefault(v.URL, v.Source),
	)
}

// vexID is a stable identifier for this document. OpenVEX wants an IRI; the
// inventory's own serial is already a URN and already unique per scan, so it is
// reused rather than minting a second identity for the same event.
func vexID(inv *airom.Inventory) string {
	if inv.Serial != "" {
		return inv.Serial
	}
	return "urn:airom:vex:" + inv.Timestamp.UTC().Format("20060102T150405Z")
}

// author names the party making the assertions. A scanner is not the supplier,
// and saying so keeps the document from being read as a vendor attestation.
func author(inv *airom.Inventory) string {
	if t := strings.TrimSpace(inv.Tool.Name); t != "" {
		return t + " (automated scan; not a supplier attestation)"
	}
	return "airom (automated scan; not a supplier attestation)"
}

func tooling(inv *airom.Inventory) string {
	name := orDefault(inv.Tool.Name, "airom")
	if v := strings.TrimSpace(inv.Tool.Version); v != "" {
		return "pkg:golang/github.com/airomhq/" + name + "@" + v
	}
	return "pkg:golang/github.com/airomhq/" + name
}

func orDefault(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
