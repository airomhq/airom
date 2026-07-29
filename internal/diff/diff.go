// Package diff compares two native AIBOM documents (schemaVersion "1") and
// reports what changed between them: components added, removed, and changed,
// keyed by the stable component ID (ARCHITECTURE.md §9.2). Version is
// deliberately not part of component identity, so a version bump surfaces as
// a field change on one component — never as a remove+add pair.
//
// The comparison is a pure function of the two documents: no scanning, no
// network, deterministic output (invariant P7).
package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

// Load reads a native AIBOM JSON document. It refuses other formats
// (CycloneDX, SARIF) explicitly: they lack the lossless fields the diff is
// keyed on, and a wrong-format file must say so rather than diff as empty.
func Load(path string) (*airom.Inventory, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- user-specified input path
	if err != nil {
		return nil, err
	}
	// Probe the version before the full decode, so a CycloneDX/SARIF file
	// reports "wrong format", not whichever field happens to unmarshal badly
	// first.
	var probe struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("%s: not a native AIBOM JSON document: %w", path, err)
	}
	if probe.SchemaVersion != "1" {
		return nil, fmt.Errorf("%s: schemaVersion %q is not a native AIBOM document (want \"1\"; generate one with 'airom scan <target> -o json=%s')",
			path, probe.SchemaVersion, path)
	}
	var inv airom.Inventory
	if err := json.Unmarshal(b, &inv); err != nil {
		return nil, fmt.Errorf("%s: not a native AIBOM JSON document: %w", path, err)
	}
	return &inv, nil
}

// FieldChange is one changed field on a component present in both documents.
type FieldChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// Change is a component present in both documents with at least one changed
// field. Component is the new-side snapshot.
type Change struct {
	Component airom.Component `json:"component"`
	Fields    []FieldChange   `json:"fields"`
}

// Result is the semantic delta between two AIBOM documents.
type Result struct {
	OldPath, NewPath string
	Old, New         *airom.Inventory

	Added   []airom.Component
	Removed []airom.Component
	Changed []Change

	Unchanged int
	// Drift lists the tooling provenance fields that differ between the two
	// documents. Non-empty means the delta cannot be attributed to the code:
	// see ProvenanceDrift.
	Drift []string
	// TestOnlySkipped counts components excluded because every occurrence is
	// test scaffolding (Component.TestOnly), summed across both documents.
	TestOnlySkipped int
}

// ProvenanceDrift reports the tooling fields that differ between two
// documents, in reading order. Empty means both were produced by the same
// binary, ruleset, and lifecycle catalog, so every difference between them is
// a difference in the code.
//
// When it is NOT empty the comparison is confounded, and quietly diffing anyway
// invents a delta. A rule added between the two scans makes components appear
// that the PR never wrote; a rule removed makes them vanish. Reproduced during
// review: two scans of one unchanged directory, differing only in scan
// configuration, reported a hosted model as removed — and gating the reverse
// direction exited 1, failing a build for AI nobody had touched.
//
// tool.version matters as much as rulesHash, because detection also lives in
// Go: the docstring region class shipped in the lexer, changing what every
// Python rule sees without moving the ruleset hash by a byte.
func ProvenanceDrift(oldInv, newInv *airom.Inventory) []string {
	var out []string
	cmp := func(label, oldV, newV string) {
		if oldV != newV {
			out = append(out, fmt.Sprintf("%s: %s → %s", label, display(oldV), display(newV)))
		}
	}
	cmp("airom version", oldInv.Tool.Version, newInv.Tool.Version)
	cmp("ruleset", oldInv.Tool.RulesVersion, newInv.Tool.RulesVersion)
	cmp("ruleset hash", shortHash(oldInv.Tool.RulesHash), shortHash(newInv.Tool.RulesHash))
	cmp("lifecycle catalog", oldInv.Tool.EOLCatalog, newInv.Tool.EOLCatalog)
	return out
}

func display(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// shortHash trims a ruleset hash to a readable prefix; the full value is in
// the documents and adds nothing to a mismatch message.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// Empty reports whether the diff found no added, removed, or changed
// components.
func (r *Result) Empty() bool {
	return len(r.Added) == 0 && len(r.Removed) == 0 && len(r.Changed) == 0
}

// GateComponents returns the components a CI gate evaluates: everything
// added plus the new-side snapshot of everything changed. Removals are not
// gated — a policy names AI you do not want to appear, and a removal is that
// policy succeeding.
func (r *Result) GateComponents() []airom.Component {
	out := make([]airom.Component, 0, len(r.Added)+len(r.Changed))
	out = append(out, r.Added...)
	for _, c := range r.Changed {
		out = append(out, c.Component)
	}
	return out
}

// Compute diffs two inventories. The scan-root application components are
// excluded — the root is the scan subject, not an AI asset, and its identity
// tracks the target name rather than any AI usage. Test-scoped components
// are excluded unless includeTests is set, mirroring every other default
// surface (docs: "Test scope").
func Compute(oldInv, newInv *airom.Inventory, includeTests bool) *Result {
	r := &Result{Old: oldInv, New: newInv, Drift: ProvenanceDrift(oldInv, newInv)}

	skip := func(inv *airom.Inventory, c *airom.Component) bool {
		if c.ID == inv.Root || c.Kind == airom.KindApplication {
			return true
		}
		if c.TestOnly && !includeTests {
			r.TestOnlySkipped++
			return true
		}
		return false
	}

	oldByID := make(map[airom.ID]*airom.Component, len(oldInv.Components))
	for i := range oldInv.Components {
		c := &oldInv.Components[i]
		if !skip(oldInv, c) {
			oldByID[c.ID] = c
		}
	}

	seen := make(map[airom.ID]bool, len(newInv.Components))
	for i := range newInv.Components {
		c := &newInv.Components[i]
		if skip(newInv, c) {
			continue
		}
		seen[c.ID] = true
		prev, ok := oldByID[c.ID]
		if !ok {
			r.Added = append(r.Added, *c)
			continue
		}
		if fields := compareComponents(prev, c); len(fields) > 0 {
			r.Changed = append(r.Changed, Change{Component: *c, Fields: fields})
		} else {
			r.Unchanged++
		}
	}

	for i := range oldInv.Components {
		c := &oldInv.Components[i]
		if _, kept := oldByID[c.ID]; kept && !seen[c.ID] {
			r.Removed = append(r.Removed, *c)
		}
	}

	sortComponents(r.Added)
	sortComponents(r.Removed)
	sort.SliceStable(r.Changed, func(i, j int) bool {
		return componentLess(&r.Changed[i].Component, &r.Changed[j].Component)
	})
	return r
}

func sortComponents(cs []airom.Component) {
	sort.SliceStable(cs, func(i, j int) bool { return componentLess(&cs[i], &cs[j]) })
}

// componentLess orders by (kind, name, id) — the reading order of the table
// writer, made total by the unique ID.
func componentLess(a, b *airom.Component) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.ID < b.ID
}

// compareComponents reports the identity- and risk-surface fields that
// differ between two snapshots of one component. Evidence churn (occurrence
// counts, detector sets) is deliberately not compared: two scans of the same
// code with different rule versions would otherwise read as wall-to-wall
// change. Confidence is compared by band for the same reason — 0.87 → 0.88
// is noise, medium → high is signal.
func compareComponents(oldC, newC *airom.Component) []FieldChange {
	var out []FieldChange
	add := func(field, oldV, newV string) {
		if oldV != newV {
			out = append(out, FieldChange{Field: field, Old: oldV, New: newV})
		}
	}

	add("kind", string(oldC.Kind), string(newC.Kind))
	add("name", oldC.Name, newC.Name)
	add("group", oldC.Group, newC.Group)
	add("version", optDisplay(oldC.Version), optDisplay(newC.Version))
	add("provider", optDisplay(oldC.Provider), optDisplay(newC.Provider))
	add("purl", oldC.PURL, newC.PURL)
	add("licenses", licensesKey(oldC.Licenses), licensesKey(newC.Licenses))
	add("confidence", oldC.Confidence.Band(), newC.Confidence.Band())
	add("risks", risksKey(oldC.Risks), risksKey(newC.Risks))
	add("vulnerabilities", vulnsKey(oldC.Vulnerabilities), vulnsKey(newC.Vulnerabilities))
	add("eol", eolKey(oldC.EOL), eolKey(newC.EOL))
	add("testOnly", boolKey(oldC.TestOnly), boolKey(newC.TestOnly))
	return out
}

// optDisplay renders a tri-state string for comparison and display: Known is
// its value, Unknown is "unknown", Absent is "".
func optDisplay(o airom.OptString) string {
	switch o.P {
	case airom.PresenceKnown:
		return o.V
	case airom.PresenceUnknown:
		return "unknown"
	default:
		return ""
	}
}

func boolKey(b bool) string {
	if b {
		return "true"
	}
	return ""
}

// licensesKey canonicalizes a license list into a sorted, comparable string.
func licensesKey(ls []airom.License) string {
	parts := make([]string, 0, len(ls))
	for _, l := range ls {
		switch {
		case l.SPDXID != "":
			parts = append(parts, l.SPDXID)
		case l.Expression != "":
			parts = append(parts, l.Expression)
		case l.Name != "":
			parts = append(parts, l.Name)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// risksKey canonicalizes the artifact-risk overlay into "id(severity)"
// entries, sorted and deduplicated.
func risksKey(rs []airom.ArtifactRisk) string {
	set := map[string]bool{}
	for _, r := range rs {
		set[fmt.Sprintf("%s(%s)", r.ID, r.Severity)] = true
	}
	return joinSet(set)
}

// vulnsKey canonicalizes the CVE overlay into sorted advisory IDs.
func vulnsKey(vs []airom.Vulnerability) string {
	set := map[string]bool{}
	for _, v := range vs {
		set[v.ID] = true
	}
	return joinSet(set)
}

// eolKey renders the lifecycle overlay: the state, plus the shutdown date
// when known. Nil means the catalog made no claim, rendered as "".
func eolKey(l *airom.Lifecycle) string {
	if l == nil {
		return ""
	}
	if l.Shutdown != nil {
		return fmt.Sprintf("%s (shutdown %s)", l.State, l.Shutdown)
	}
	return string(l.State)
}

func joinSet(set map[string]bool) string {
	parts := make([]string, 0, len(set))
	for p := range set {
		parts = append(parts, p)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// minLocation returns the smallest (path:line) occurrence of a component, or
// "" if it has none — the same deterministic evidence pointer the compliance
// report uses.
func minLocation(c *airom.Component) string {
	best := ""
	for _, o := range c.Evidence.Occurrences {
		if o.Location.Path == "" {
			continue
		}
		loc := o.Location.Path
		if o.Location.Line > 0 {
			loc = fmt.Sprintf("%s:%d", o.Location.Path, o.Location.Line)
		}
		if best == "" || loc < best {
			best = loc
		}
	}
	return best
}

// confidence renders a component confidence with the shared §6.2 formatting.
func confidence(c airom.Confidence) string { return writer.FormatConfidence(c) }
