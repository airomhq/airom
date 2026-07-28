// Package compliance maps a named AI-governance framework's controls onto an
// assembled AIROM inventory. For each control it decides met / gap / manual and
// attaches the component evidence behind the verdict.
//
// It is a mapping engine, NEVER a certifier. Controls a static scan cannot
// verify are marked manual and carry no score; a "met" is only ever asserted
// with concrete component evidence. Frameworks ship as embedded YAML specs
// (specs/<id>.yaml) — controls are data, so adding one is a spec PR, no Go.
package compliance

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/airomhq/airom/pkg/airom"
)

//go:embed specs/*.yaml
var specFS embed.FS

// framework is a parsed, compiled framework spec.
type framework struct {
	ID       string    `yaml:"id"`
	Name     string    `yaml:"name"`
	Version  string    `yaml:"version"`
	URL      string    `yaml:"url"`
	Controls []control `yaml:"controls"`
}

// control is one requirement plus its single mapping directive.
type control struct {
	ID         string `yaml:"id"`
	Title      string `yaml:"title"`
	Text       string `yaml:"text"`
	Ref        string `yaml:"ref"`
	EvidenceOf string `yaml:"evidence_of"`
	GapIf      string `yaml:"gap_if"`
	Manual     bool   `yaml:"manual"`

	evExpr  *expr // compiled EvidenceOf
	gapExpr *expr // compiled GapIf
}

// loadFrameworks parses and validates every embedded spec. A malformed spec is
// a build-time-shaped failure (it ships in the binary), so this is called once
// and any error means the binary itself is broken.
func loadFrameworks() (map[string]*framework, error) {
	entries, err := fs.Glob(specFS, "specs/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	out := make(map[string]*framework, len(entries))
	for _, path := range entries {
		data, err := specFS.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var fw framework
		if err := yaml.Unmarshal(data, &fw); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := validate(&fw); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if _, dup := out[fw.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate framework id %q", path, fw.ID)
		}
		out[fw.ID] = &fw
	}
	return out, nil
}

// validate enforces the spec contract and compiles the mapping expressions:
// non-empty identity, unique control ids, and EXACTLY ONE of
// evidence_of / gap_if / manual per control.
func validate(fw *framework) error {
	if fw.ID == "" || fw.Name == "" || fw.Version == "" {
		return fmt.Errorf("framework id, name, and version are required")
	}
	// "gap" is reserved: the --fail-on grammar reads `compliance:gap` as
	// "any gap", so a framework with that id would be unreachable by name.
	if fw.ID == "gap" {
		return fmt.Errorf("framework id %q is reserved (collides with the compliance:gap selector)", fw.ID)
	}
	if len(fw.Controls) == 0 {
		return fmt.Errorf("framework %q has no controls", fw.ID)
	}
	seen := map[string]bool{}
	for i := range fw.Controls {
		c := &fw.Controls[i]
		if c.ID == "" || c.Title == "" {
			return fmt.Errorf("control %d: id and title are required", i)
		}
		if seen[c.ID] {
			return fmt.Errorf("duplicate control id %q", c.ID)
		}
		seen[c.ID] = true

		n := 0
		if c.EvidenceOf != "" {
			n++
		}
		if c.GapIf != "" {
			n++
		}
		if c.Manual {
			n++
		}
		if n != 1 {
			return fmt.Errorf("control %q: exactly one of evidence_of / gap_if / manual is required (got %d)", c.ID, n)
		}
		var err error
		if c.EvidenceOf != "" {
			if c.evExpr, err = compile(c.EvidenceOf); err != nil {
				return fmt.Errorf("control %q evidence_of: %w", c.ID, err)
			}
		}
		if c.GapIf != "" {
			if c.gapExpr, err = compile(c.GapIf); err != nil {
				return fmt.Errorf("control %q gap_if: %w", c.ID, err)
			}
		}
	}
	return nil
}

// IDs returns the known framework ids, sorted — for flag validation and error
// messages. Panics only if an embedded spec is malformed (a broken binary).
func IDs() []string {
	fws, err := loadFrameworks()
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(fws))
	for id := range fws {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// HasFramework reports whether id names an embedded framework — for
// --fail-on compliance:<framework> validation.
func HasFramework(id string) bool {
	fws, err := loadFrameworks()
	if err != nil {
		return false
	}
	_, ok := fws[id]
	return ok
}

// HasControl reports whether framework id defines control controlID — for
// --fail-on compliance:<framework>:<control> validation.
func HasControl(id, controlID string) bool {
	fws, err := loadFrameworks()
	if err != nil {
		return false
	}
	fw, ok := fws[id]
	if !ok {
		return false
	}
	for i := range fw.Controls {
		if fw.Controls[i].ID == controlID {
			return true
		}
	}
	return false
}

// Evaluate maps each requested framework onto inv, returning one
// ComplianceResult per framework in the order requested (deduplicated). An
// unknown framework id is an error naming the valid set.
func Evaluate(inv *airom.Inventory, frameworkIDs []string, includeTests bool) ([]airom.ComplianceResult, error) {
	fws, err := loadFrameworks()
	if err != nil {
		return nil, err
	}
	var results []airom.ComplianceResult
	seen := map[string]bool{}
	for _, id := range frameworkIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		fw, ok := fws[id]
		if !ok {
			return nil, fmt.Errorf("unknown compliance framework %q; valid: %s", id, strings.Join(IDs(), ", "))
		}
		results = append(results, evaluate(fw, inv, includeTests))
	}
	return results, nil
}

// scoreMet / scoreGap are the fixed conformance scores whose addresses fill
// ControlOutcome.Score (nil for manual). Shared, read-only.
var (
	scoreMet = 1.0
	scoreGap float64 // 0.0
)

// evaluate maps one framework onto the inventory. Controls stay in
// spec-declared order (the framework's own logical order) — deterministic
// because the embedded spec is fixed bytes.
func evaluate(fw *framework, inv *airom.Inventory, includeTests bool) airom.ComplianceResult {
	out := airom.ComplianceResult{
		Framework: fw.ID,
		Name:      fw.Name,
		Version:   fw.Version,
		URL:       fw.URL,
		Controls:  make([]airom.ControlOutcome, 0, len(fw.Controls)),
	}
	for i := range fw.Controls {
		out.Controls = append(out.Controls, evalControl(&fw.Controls[i], inv, includeTests))
	}
	return out
}

func evalControl(c *control, inv *airom.Inventory, includeTests bool) airom.ControlOutcome {
	oc := airom.ControlOutcome{ID: c.ID, Title: c.Title, Text: c.Text, Ref: c.Ref}

	switch {
	case c.Manual:
		oc.State = airom.ControlManual
		oc.Rationale = "not automatable by a static scan — requires manual attestation"
		return oc

	case c.evExpr != nil:
		matches := c.evExpr.match(inv, includeTests)
		if len(matches) > 0 {
			oc.State, oc.Score = airom.ControlMet, &scoreMet
			oc.Evidence = matches
			oc.Rationale = fmt.Sprintf("%d component(s) provide supporting evidence", len(matches))
		} else {
			oc.State, oc.Score = airom.ControlGap, &scoreGap
			oc.Rationale = "no supporting evidence found in the inventory"
		}
		return oc

	default: // gapExpr != nil (validate guarantees exactly one directive)
		matches := c.gapExpr.match(inv, includeTests)
		if len(matches) > 0 {
			oc.State, oc.Score = airom.ControlGap, &scoreGap
			oc.Counter = matches
			oc.Rationale = fmt.Sprintf("%d component(s) constitute a gap", len(matches))
		} else {
			oc.State, oc.Score = airom.ControlMet, &scoreMet
			oc.Rationale = "no gap present in the inventory"
		}
		return oc
	}
}
