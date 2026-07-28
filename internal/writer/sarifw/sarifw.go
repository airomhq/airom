package sarifw

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

func init() {
	writer.Register("sarif", func(o writer.Options) writer.Writer { return New(o) })
}

// Envelope constants (docs/mapping.md §3.1, §7.3).
const (
	schemaURI      = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion   = "2.1.0"
	columnKind     = "utf16CodeUnits"
	informationURI = "https://github.com/airomhq/airom"
	helpURI        = "https://github.com/airomhq/airom/blob/main/docs/"
	srcRootID      = "SRCROOT"
	fingerprintKey = "airomComponentIdentity/v1"
)

// Writer projects an Inventory to SARIF 2.1.0. strict selects the §7.1
// encoding: default emits level "note"; strict emits kind "informational".
type Writer struct{ strict, includeTests bool }

// New builds a SARIF writer from options. SARIFStrict flips the §7.1
// level/kind encoding globally.
func New(o writer.Options) Writer {
	return Writer{strict: o.SARIFStrict, includeTests: o.IncludeTests}
}

// Format implements writer.Writer.
func (Writer) Format() string { return "sarif" }

// Write emits the Inventory as indented SARIF 2.1.0 JSON with a trailing
// newline. Deterministic (P7): rules sorted by id; results in (component ID,
// occurrence path, line, detector) order; property bags are maps, which
// encoding/json key-sorts.
func (wr Writer) Write(w io.Writer, inv *airom.Inventory) error {
	rep := wr.build(inv)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}

// build assembles the SARIF report from the inventory.
func (wr Writer) build(inv *airom.Inventory) sarifReport {
	comps := scannedComponents(inv, wr.includeTests)
	rules, ruleIndex := buildRules(comps)
	riskRules, riskIndex := buildRiskRules(comps, len(rules))
	rules = append(rules, riskRules...)
	cveRules, cveIndex := buildCVERules(comps, len(rules))
	rules = append(rules, cveRules...)
	eolRules, eolIndex := buildEOLRules(comps, len(rules))
	rules = append(rules, eolRules...)

	results := wr.buildResults(comps, ruleIndex)
	results = append(results, buildRiskResults(comps, riskIndex)...)
	results = append(results, buildCVEResults(comps, cveIndex)...)
	results = append(results, buildEOLResults(comps, eolIndex)...)

	run := sarifRun{
		Tool:        buildTool(inv, rules),
		ColumnKind:  columnKind,
		Invocations: []sarifInvocation{buildInvocation(inv)},
		Results:     results,
	}

	// SRCROOT anchors artifact URIs to a filesystem root, so it is emitted only
	// for a real path target: always for a dir scan, and for a repo scan only
	// when the target is a local worktree (not a remote URL). A remote repo's
	// provenance travels via versionControlProvenance below instead. (Phase 10
	// review, writers-conformance.)
	if inv.Source.Kind == "dir" || (inv.Source.Kind == "repo" && !isRemoteGitTarget(inv.Source.Target)) {
		run.OriginalURIBaseIDs = map[string]sarifArtifactLocation{
			srcRootID: {URI: srcRootURI(inv.Source.Target)},
		}
	}
	if g := inv.Source.Git; g != nil && g.Remote != "" {
		run.VersionControlProvenance = []sarifVCS{{RepositoryURI: g.Remote, RevisionID: g.Commit}}
	}

	return sarifReport{
		Schema:  schemaURI,
		Version: sarifVersion,
		Runs:    []sarifRun{run},
	}
}

// scannedComponents returns every component that produces results — every
// kind except the scan-root application component (§7.3), and, unless
// includeTests, those whose evidence is all test scaffolding.
//
// SARIF drives code-scanning alerts, so its cost of noise is the highest of any
// output: an alert on a rule-pack fixture is a notification a human must
// dismiss, and enough of them train the team to dismiss the real ones. The
// components remain in the native and CycloneDX documents.
func scannedComponents(inv *airom.Inventory, includeTests bool) []airom.Component {
	out := make([]airom.Component, 0, len(inv.Components))
	for _, c := range inv.Components {
		if c.Kind == airom.KindApplication || c.ID == inv.Root {
			continue
		}
		if c.TestOnly && !includeTests {
			continue
		}
		if !includeTests {
			// Component-level filtering is not enough here. SARIF annotates
			// individual LINES, so a genuinely production component that also
			// appears in fixtures — `openai`, declared in requirements.txt and
			// imported by three test files — would still plant alerts inside
			// testdata/. Prune the occurrences too, and every downstream builder
			// (detector results, risks, CVEs, EOL, locations) inherits it from
			// this one place. A non-test-only component always keeps at least
			// one occurrence, by definition.
			c.Evidence.Occurrences = airom.ProductionOccurrences(c.Evidence.Occurrences)
			// Risks carry their OWN provenance (ArtifactRisk.Occurrence), which
			// the line above does not touch. Without this, a production
			// dependency whose unsafe-load site happens to live in a test file
			// still raises a security alert inside tests/ — the precise leak the
			// pruning exists to stop, just arriving by a second route.
			c.Risks = productionRisks(c.Risks)
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// productionRisks drops risks whose own occurrence sits in test scaffolding.
// A risk with no occurrence at all is kept: it is attached to a component that
// already survived the test-scope cut, and dropping a security finding for lack
// of provenance would be the wrong way to be wrong.
func productionRisks(risks []airom.ArtifactRisk) []airom.ArtifactRisk {
	out := make([]airom.ArtifactRisk, 0, len(risks))
	for _, r := range risks {
		if r.Occurrence != nil && airom.IsTestPath(r.Occurrence.Location.Path) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// buildRules collects one rule per distinct DetectorID across all
// occurrences, sorted by id (§7.3). It returns the rules and an id→index
// map for result references.
func buildRules(comps []airom.Component) ([]sarifRule, map[string]int) {
	methods := map[string]airom.DetectionMethod{}
	ids := make([]string, 0)
	for _, c := range comps {
		for _, o := range c.Evidence.Occurrences {
			if _, seen := methods[o.DetectorID]; !seen {
				methods[o.DetectorID] = o.Method
				ids = append(ids, o.DetectorID)
			}
		}
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		index[id] = i
		rules = append(rules, sarifRule{
			ID:                   id,
			Name:                 upperCamelCase(id),
			ShortDescription:     sarifText{Text: fmt.Sprintf("Components identified by the %s detector.", id)},
			DefaultConfiguration: sarifConfig{Level: "note"},
			HelpURI:              helpURI,
			Properties:           map[string]any{"airom:method": string(methods[id])},
		})
	}
	return rules, index
}

// buildRiskRules adds one security rule per artifact-risk type present, id
// "risk/<slug>", carrying the GitHub `security-severity` property so the
// findings bucket in the Code Scanning UI. Indices continue from offset (the
// detector-rule count) so risk results can reference them. Deterministic:
// rules sorted by slug.
func buildRiskRules(comps []airom.Component, offset int) ([]sarifRule, map[string]int) {
	present := map[airom.RiskID]bool{}
	for _, c := range comps {
		for _, r := range c.Risks {
			present[r.ID] = true
		}
	}
	if len(present) == 0 {
		return nil, nil
	}
	ids := make([]airom.RiskID, 0, len(present))
	for id := range present {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return airom.RiskByID(ids[i]).Slug < airom.RiskByID(ids[j]).Slug })

	rules := make([]sarifRule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		meta := airom.RiskByID(id)
		ruleID := "risk/" + meta.Slug
		index[ruleID] = offset + i
		rules = append(rules, sarifRule{
			ID:                   ruleID,
			Name:                 upperCamelCase(ruleID),
			ShortDescription:     sarifText{Text: meta.Description},
			DefaultConfiguration: sarifConfig{Level: riskLevel(meta.Severity)},
			HelpURI:              helpURI + "risks.md#" + meta.Slug,
			Properties: map[string]any{
				"security-severity":   securitySeverity(meta.Severity),
				"airom:risk.severity": string(meta.Severity),
			},
		})
	}
	return rules, index
}

// buildRiskResults emits one security result per (component, risk), in
// (component, sorted-risk) order — c.Risks is already sorted by the assembler.
func buildRiskResults(comps []airom.Component, index map[string]int) []sarifResult {
	if len(index) == 0 {
		return nil
	}
	var results []sarifResult
	for _, c := range comps {
		for _, r := range c.Risks {
			meta := airom.RiskByID(r.ID)
			ruleID := "risk/" + meta.Slug
			res := sarifResult{
				RuleID:     ruleID,
				RuleIndex:  index[ruleID],
				Level:      riskLevel(meta.Severity),
				Message:    sarifText{Text: riskMessage(c, r, meta)},
				Locations:  riskLocations(r),
				Properties: map[string]any{"airom:componentId": string(c.ID), "airom:risk.severity": string(r.Severity)},
			}
			if len(r.Detail) > 0 {
				res.Properties["airom:risk.symbols"] = strings.Join(r.Detail, "|")
			}
			results = append(results, res)
		}
	}
	return results
}

// riskLocations projects a risk's provenance occurrence to a SARIF location,
// or an empty slice when the risk carries none.
func riskLocations(r airom.ArtifactRisk) []sarifLocation {
	if r.Occurrence == nil {
		return []sarifLocation{}
	}
	o := *r.Occurrence
	return []sarifLocation{{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: o.Location.Path, URIBaseID: srcRootID},
			Region:           buildRegion(o),
		},
	}}
}

// riskMessage renders the security-result headline.
func riskMessage(c airom.Component, r airom.ArtifactRisk, meta airom.RiskMeta) string {
	msg := fmt.Sprintf("%s in %q", meta.Title, c.Name)
	if len(r.Detail) > 0 {
		msg += ": " + strings.Join(r.Detail, ", ")
	}
	return msg
}

// riskLevel maps a severity bucket to a SARIF result level.
func riskLevel(s airom.RiskSeverity) string {
	switch s {
	case airom.RiskHigh:
		return "error"
	case airom.RiskMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps a severity bucket to the GitHub Code Scanning
// `security-severity` bucket marker (a 0–10 string, NOT a CVSS claim).
func securitySeverity(s airom.RiskSeverity) string {
	switch s {
	case airom.RiskHigh:
		return "8.0"
	case airom.RiskMedium:
		return "5.0"
	default:
		return "3.0"
	}
}

// buildCVERules adds one security rule per distinct CVE present, id
// "cve/<id>", carrying `security-severity` — a real CVSS base score here, not
// the synthetic marker the risk rules use. Indices continue from offset so CVE
// results can reference them. Deterministic: rules sorted by id, each described
// by its first-seen advisory (component order is already ID-sorted).
func buildCVERules(comps []airom.Component, offset int) ([]sarifRule, map[string]int) {
	rep := map[string]airom.Vulnerability{}
	ids := make([]string, 0)
	for _, c := range comps {
		for _, v := range c.Vulnerabilities {
			if _, seen := rep[v.ID]; !seen {
				rep[v.ID] = v
				ids = append(ids, v.ID)
			}
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		v := rep[id]
		ruleID := "cve/" + id
		index[ruleID] = offset + i
		props := map[string]any{
			"security-severity":  cveSecuritySeverity(v),
			"airom:cve.severity": string(v.Severity),
		}
		if v.Vector != "" {
			props["airom:cve.vector"] = v.Vector
		}
		desc := v.Summary
		if desc == "" {
			desc = fmt.Sprintf("Known vulnerability %s.", id)
		}
		rules = append(rules, sarifRule{
			ID:                   ruleID,
			Name:                 upperCamelCase(ruleID),
			ShortDescription:     sarifText{Text: desc},
			DefaultConfiguration: sarifConfig{Level: cveLevel(v.Severity)},
			HelpURI:              v.URL,
			Properties:           props,
		})
	}
	return rules, index
}

// buildCVEResults emits one security result per (component, CVE), in
// (component, sorted-CVE) order — c.Vulnerabilities is sorted by the OSV
// enricher. Each result anchors to the component's primary sighting (the
// manifest line declaring the vulnerable package).
func buildCVEResults(comps []airom.Component, index map[string]int) []sarifResult {
	if len(index) == 0 {
		return nil
	}
	var results []sarifResult
	for _, c := range comps {
		for _, v := range c.Vulnerabilities {
			ruleID := "cve/" + v.ID
			props := map[string]any{
				"airom:componentId":  string(c.ID),
				"airom:cve.severity": string(v.Severity),
			}
			if v.Score > 0 {
				props["airom:cve.score"] = v.Score
			}
			if v.Fixed != "" {
				props["airom:cve.fixed"] = v.Fixed
			}
			results = append(results, sarifResult{
				RuleID:     ruleID,
				RuleIndex:  index[ruleID],
				Level:      cveLevel(v.Severity),
				Message:    sarifText{Text: cveMessage(c, v)},
				Locations:  primaryLocations(c),
				Properties: props,
			})
		}
	}
	return results
}

// primaryLocations projects a component's lowest (path, line) occurrence to a
// single SARIF location, or an empty slice when it carries none. CVEs are a
// property of the package, so they anchor to where the package was declared.
func primaryLocations(c airom.Component) []sarifLocation {
	occs := c.Evidence.Occurrences
	if len(occs) == 0 {
		return []sarifLocation{}
	}
	best := occs[0]
	for _, o := range occs[1:] {
		if o.Location.Path != best.Location.Path {
			if o.Location.Path < best.Location.Path {
				best = o
			}
			continue
		}
		if o.Location.Line < best.Location.Line {
			best = o
		}
	}
	if best.Location.Path == "" {
		return []sarifLocation{}
	}
	return []sarifLocation{{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: best.Location.Path, URIBaseID: srcRootID},
			Region:           buildRegion(best),
		},
	}}
}

// cveMessage renders the security-result headline.
func cveMessage(c airom.Component, v airom.Vulnerability) string {
	name := c.Name
	if ver, ok := c.Version.Value(); ok {
		name = fmt.Sprintf("%s %s", name, ver)
	}
	msg := fmt.Sprintf("%s (%s) affects %s", v.ID, v.Severity, name)
	if v.Fixed != "" {
		msg += fmt.Sprintf("; fixed in %s", v.Fixed)
	}
	return msg
}

// cveLevel maps a CVE severity bucket to a SARIF result level.
func cveLevel(s airom.VulnSeverity) string {
	switch s {
	case airom.VulnCritical, airom.VulnHigh:
		return "error"
	case airom.VulnMedium:
		return "warning"
	default:
		return "note"
	}
}

// cveSecuritySeverity is the GitHub Code Scanning `security-severity` value: the
// real CVSS base score when known, else a bucket midpoint from the text
// severity so the finding still sorts into the right band.
func cveSecuritySeverity(v airom.Vulnerability) string {
	if v.Score > 0 {
		return fmt.Sprintf("%.1f", v.Score)
	}
	switch v.Severity {
	case airom.VulnCritical:
		return "9.5"
	case airom.VulnHigh:
		return "8.0"
	case airom.VulnMedium:
		return "5.0"
	case airom.VulnLow:
		return "3.0"
	default:
		return "0.0"
	}
}

// buildEOLRules adds one rule per distinct model lifecycle finding, id
// "eol/<provider>/<model>". Only models with an announced retirement get one:
// "supported" is good news and "unknown" is no news, and neither belongs in a
// findings list. Indices continue from offset. Deterministic: sorted by id.
//
// No `security-severity` property here, unlike the risk and CVE rules — a
// scheduled retirement is an availability fact, not a security finding, and
// tagging it as one would inflate a Code Scanning security dashboard with
// something no patch can fix.
func buildEOLRules(comps []airom.Component, offset int) ([]sarifRule, map[string]int) {
	rep := map[string]airom.Component{}
	ids := make([]string, 0)
	for _, c := range comps {
		if !eolReportable(c) {
			continue
		}
		id := eolRuleID(c)
		if _, seen := rep[id]; !seen {
			rep[id] = c
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		c := rep[id]
		e := c.EOL
		index[id] = offset + i
		props := map[string]any{"airom:eol.state": string(e.State)}
		if e.Shutdown != nil {
			props["airom:eol.shutdownDate"] = e.Shutdown.String()
		}
		if e.Replacement != "" {
			props["airom:eol.replacement"] = e.Replacement
		}
		rules = append(rules, sarifRule{
			ID:                   id,
			Name:                 upperCamelCase(id),
			ShortDescription:     sarifText{Text: eolRuleDescription(c)},
			DefaultConfiguration: sarifConfig{Level: eolLevel(e.State)},
			HelpURI:              e.SourceURL,
			Properties:           props,
		})
	}
	return rules, index
}

// buildEOLResults emits one result per affected model, anchored to where the
// model is referenced in the code — the line a developer has to change.
func buildEOLResults(comps []airom.Component, index map[string]int) []sarifResult {
	if len(index) == 0 {
		return nil
	}
	var results []sarifResult
	for _, c := range comps {
		if !eolReportable(c) {
			continue
		}
		id := eolRuleID(c)
		e := c.EOL
		props := map[string]any{
			"airom:componentId": string(c.ID),
			"airom:eol.state":   string(e.State),
		}
		if e.DaysRemaining != nil {
			props["airom:eol.daysRemaining"] = *e.DaysRemaining
		}
		// Only meaningful alongside a replacement, and CDX nests it the same
		// way: one struct must not describe itself two different ways.
		if e.Replacement != "" && e.ReplacementState != "" {
			props["airom:eol.replacementState"] = string(e.ReplacementState)
		}
		results = append(results, sarifResult{
			RuleID:    id,
			RuleIndex: index[id],
			Level:     eolLevel(e.State),
			Message:   sarifText{Text: eolMessage(c)},
			// EVERY sighting, not just the primary one. A CVE is fixed by
			// bumping one version pin, so anchoring to the declaration site is
			// enough; a retired model is a literal that has to change at each
			// call site. Showing one would let a developer clear the alert while
			// the other files keep calling a model that no longer answers.
			Locations:  allLocations(c),
			Properties: props,
		})
	}
	return results
}

// allLocations projects every located sighting of a component, in the same
// (path, line) order the inventory results use, so a reader sees each place the
// finding applies. Falls back to an empty slice when nothing is located.
func allLocations(c airom.Component) []sarifLocation {
	occs := append([]airom.Occurrence(nil), c.Evidence.Occurrences...)
	sort.SliceStable(occs, func(i, j int) bool {
		if occs[i].Location.Path != occs[j].Location.Path {
			return occs[i].Location.Path < occs[j].Location.Path
		}
		return occs[i].Location.Line < occs[j].Location.Line
	})
	out := make([]sarifLocation, 0, len(occs))
	for _, o := range occs {
		if o.Location.Path == "" {
			continue
		}
		out = append(out, sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: o.Location.Path, URIBaseID: srcRootID},
				Region:           buildRegion(o),
			},
		})
	}
	return out
}

// eolReportable reports whether a component carries a lifecycle finding worth
// listing: an announced retirement. A supported model is not a finding, and an
// absent record is not a claim.
func eolReportable(c airom.Component) bool {
	return c.EOL != nil && (c.EOL.State == airom.EOLRetired || c.EOL.State == airom.EOLDeprecated)
}

// eolProvider is the provider label, rendered one way everywhere. A
// provider-less component cannot reach this from a scan (Enrich skips it), but
// an SDK-built inventory can, and "gpt-4 () is deprecated" reads like a bug.
func eolProvider(c airom.Component) string {
	if p, ok := c.Provider.Value(); ok && strings.TrimSpace(p) != "" {
		return p
	}
	return "unknown-provider"
}

// eolRuleID is "eol/<provider>/<model>" — provider-qualified because the same
// model name can exist on platforms with different retirement schedules.
func eolRuleID(c airom.Component) string {
	return "eol/" + eolProvider(c) + "/" + c.Name
}

// eolRuleDescription states the rule's standing fact.
func eolRuleDescription(c airom.Component) string {
	e := c.EOL
	if e.State == airom.EOLRetired {
		if e.Shutdown != nil {
			return fmt.Sprintf("%s was retired by its provider on %s and no longer serves requests.", c.Name, e.Shutdown)
		}
		return fmt.Sprintf("%s has been retired by its provider.", c.Name)
	}
	if e.Shutdown != nil {
		return fmt.Sprintf("%s is deprecated and stops serving requests on %s.", c.Name, e.Shutdown)
	}
	return fmt.Sprintf("%s is deprecated by its provider.", c.Name)
}

// eolMessage renders the per-occurrence headline: what happens, when, and what
// to move to — including whether that target is itself on the way out.
func eolMessage(c airom.Component) string {
	e := c.EOL
	var b strings.Builder
	provider := eolProvider(c)
	if e.State == airom.EOLRetired {
		fmt.Fprintf(&b, "%s (%s) is retired", c.Name, provider)
		if e.Shutdown != nil {
			fmt.Fprintf(&b, " — shut down %s", e.Shutdown)
		}
	} else {
		fmt.Fprintf(&b, "%s (%s) is deprecated", c.Name, provider)
		if e.Shutdown != nil {
			fmt.Fprintf(&b, " — shuts down %s", e.Shutdown)
			if e.DaysRemaining != nil && *e.DaysRemaining >= 0 {
				fmt.Fprintf(&b, " (%d days)", *e.DaysRemaining)
			}
		}
	}
	if n := len(c.Evidence.Occurrences); n > 1 {
		// The literal has to change at every call site, so say how many.
		fmt.Fprintf(&b, "; referenced at %d sites", n)
	}
	if e.Replacement != "" {
		fmt.Fprintf(&b, "; migrate to %s", e.Replacement)
		// Say so when the recommended target is itself scheduled to go: sending
		// someone onto a dead model is worse than saying nothing.
		switch e.ReplacementState {
		case airom.EOLRetired:
			b.WriteString(" (note: also retired — check the provider for a current model)")
		case airom.EOLDeprecated:
			b.WriteString(" (note: also deprecated)")
		}
	}
	return b.String()
}

// eolLevel maps a lifecycle state to a SARIF result level: a retired model is
// broken today (error), a deprecation is a deadline (warning).
func eolLevel(s airom.EOLState) string {
	if s == airom.EOLRetired {
		return "error"
	}
	return "warning"
}

// buildTool assembles tool.driver (§3.1).
func buildTool(inv *airom.Inventory, rules []sarifRule) sarifTool {
	d := sarifDriver{
		Name:            inv.Tool.Name,
		SemanticVersion: inv.Tool.Version,
		InformationURI:  informationURI,
		Rules:           rules,
	}
	props := map[string]any{}
	if inv.Tool.Commit != "" {
		props["airom:tool.commit"] = inv.Tool.Commit
	}
	if inv.Tool.RulesVersion != "" {
		props["airom:rules.version"] = inv.Tool.RulesVersion
	}
	if inv.Tool.RulesHash != "" {
		props["airom:rules.hash"] = inv.Tool.RulesHash
	}
	if inv.Tool.EOLCatalog != "" {
		props["airom:eol.catalog"] = inv.Tool.EOLCatalog
	}
	if len(props) > 0 {
		d.Properties = props
	}
	return sarifTool{Driver: d}
}

// buildInvocation assembles the single invocation object: a completed scan
// is successful even with Unknowns (P6, §3.11), which surface as
// toolExecutionNotifications rather than results.
func buildInvocation(inv *airom.Inventory) sarifInvocation {
	iv := sarifInvocation{
		ExecutionSuccessful: true,
		EndTimeUTC:          inv.Timestamp.UTC().Format(time.RFC3339),
	}
	for _, u := range inv.Unknowns {
		n := sarifNotification{
			Message:    sarifText{Text: u.Reason},
			Level:      "note",
			Properties: map[string]any{"airom:detectorId": u.DetectorID},
		}
		if u.Path != "" {
			n.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: u.Path},
				},
			}}
		}
		iv.ToolExecutionNotifications = append(iv.ToolExecutionNotifications, n)
	}
	return iv
}

// buildResults emits one result per occurrence, in (component ID, path,
// line, detector) order (§7.3).
func (wr Writer) buildResults(comps []airom.Component, ruleIndex map[string]int) []sarifResult {
	results := make([]sarifResult, 0)
	for _, c := range comps {
		occs := append([]airom.Occurrence(nil), c.Evidence.Occurrences...)
		sort.SliceStable(occs, func(i, j int) bool {
			if occs[i].Location.Path != occs[j].Location.Path {
				return occs[i].Location.Path < occs[j].Location.Path
			}
			if occs[i].Location.Line != occs[j].Location.Line {
				return occs[i].Location.Line < occs[j].Location.Line
			}
			return occs[i].DetectorID < occs[j].DetectorID
		})
		for _, o := range occs {
			results = append(results, wr.buildResult(c, o, ruleIndex))
		}
	}
	return results
}

// buildResult projects one Occurrence to a SARIF result (§3.8, §7.1, §7.2).
func (wr Writer) buildResult(c airom.Component, o airom.Occurrence, ruleIndex map[string]int) sarifResult {
	loc := sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: o.Location.Path, URIBaseID: srcRootID},
			Region:           buildRegion(o),
		},
	}
	if o.Symbol != "" {
		loc.LogicalLocations = []sarifLogicalLocation{{Name: o.Symbol}}
	}

	res := sarifResult{
		RuleID:              o.DetectorID,
		RuleIndex:           ruleIndex[o.DetectorID],
		Message:             sarifText{Text: messageText(c)},
		Locations:           []sarifLocation{loc},
		PartialFingerprints: map[string]string{fingerprintKey: fingerprint(o.DetectorID, string(c.ID), o.Location.Path)},
		Properties:          resultProperties(c, o),
	}
	// §7.1: default level "note" (kind omitted); strict kind "informational"
	// (level omitted).
	if wr.strict {
		res.Kind = "informational"
	} else {
		res.Level = "note"
	}
	return res
}

// buildRegion maps a Location to a SARIF region, or nil for a whole-file
// sighting (line 0), which carries a physicalLocation with no region (§6.1).
func buildRegion(o airom.Occurrence) *sarifRegion {
	if o.Location.Line == 0 {
		return nil
	}
	r := &sarifRegion{StartLine: o.Location.Line}
	if o.Location.Column > 0 {
		r.StartColumn = o.Location.Column
	}
	if o.Location.EndLine > 0 {
		r.EndLine = o.Location.EndLine
	}
	if o.Location.EndColumn > 0 {
		r.EndColumn = o.Location.EndColumn
	}
	if o.Snippet != "" {
		r.Snippet = &sarifText{Text: o.Snippet}
	}
	return r
}

// resultProperties builds the result property bag (§3.8, §6.5). Confidences
// are JSON numbers (§6.2); the rest are strings. The map key-sorts on encode.
func resultProperties(c airom.Component, o airom.Occurrence) map[string]any {
	p := map[string]any{
		"airom:componentId":           string(c.ID),
		"airom:kind":                  string(c.Kind),
		"airom:confidence":            writer.ConfidenceNumber(c.Confidence),
		"airom:occurrence.confidence": writer.ConfidenceNumber(o.Confidence),
	}
	if v, ok := c.Provider.Value(); ok {
		p["airom:provider"] = v
	}
	if c.PURL != "" {
		p["airom:purl"] = c.PURL
	}
	// Legacy inline signal, kept for one release; the authoritative risk output
	// is the security results keyed to the risk/<slug> rules.
	for _, r := range c.Risks {
		if r.ID == airom.RiskPickleImport {
			p["airom:pickle.risk"] = string(r.Severity)
		}
	}
	return p
}

// messageText renders the non-normative §7.3 headline:
// "<kind> '<group/name>' [<version>] detected (confidence <c>)".
func messageText(c airom.Component) string {
	name := c.Name
	if c.Group != "" {
		name = c.Group + "/" + c.Name
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s '%s'", c.Kind, name)
	if v, ok := c.Version.Value(); ok {
		fmt.Fprintf(&b, " [%s]", v)
	}
	fmt.Fprintf(&b, " detected (confidence %s)", writer.FormatConfidence(c.Confidence))
	return b.String()
}

// fingerprint is the §7.2 recipe: lowercase hex(sha256(detectorID | componentID
// | path)) — deliberately line-free so fingerprints survive code motion.
func fingerprint(detectorID, componentID, path string) string {
	sum := sha256.Sum256([]byte(detectorID + "|" + componentID + "|" + path))
	return hex.EncodeToString(sum[:])
}

// srcRootURI renders a scanned path target as a file:///…/ base URI (§3.1).
// isRemoteGitTarget reports whether a repo target is a remote address (URL or
// scp-style) rather than a local worktree path.
func isRemoteGitTarget(target string) bool {
	if strings.Contains(target, "://") { // https://, git://, ssh://, …
		return true
	}
	// scp-style "git@github.com:org/repo.git": '@' and ':' before any '/'.
	if i := strings.IndexByte(target, ':'); i > 0 {
		if !strings.ContainsRune(target[:i], '/') && strings.ContainsRune(target[:i], '@') {
			return true
		}
	}
	return false
}

func srcRootURI(target string) string {
	p := filepath.ToSlash(target)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	u := url.URL{Scheme: "file", Path: p}
	return u.String()
}

// upperCamelCase derives a rule name from a detector id, treating every
// non-alphanumeric rune as a word boundary: "rules/openai/model-literal"
// → "RulesOpenaiModelLiteral" (§7.3).
func upperCamelCase(id string) string {
	var b strings.Builder
	newWord := true
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
			if newWord {
				b.WriteRune(r - ('a' - 'A'))
			} else {
				b.WriteRune(r)
			}
			newWord = false
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			newWord = false
		default:
			newWord = true
		}
	}
	return b.String()
}
