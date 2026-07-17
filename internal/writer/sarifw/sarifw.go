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

	"github.com/Roro1727/airom/internal/writer"
	"github.com/Roro1727/airom/pkg/airom"
)

func init() {
	writer.Register("sarif", func(o writer.Options) writer.Writer { return New(o) })
}

// Envelope constants (docs/mapping.md §3.1, §7.3).
const (
	schemaURI      = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion   = "2.1.0"
	columnKind     = "utf16CodeUnits"
	informationURI = "https://github.com/Roro1727/airom"
	helpURI        = "https://github.com/Roro1727/airom/blob/main/docs/"
	srcRootID      = "SRCROOT"
	fingerprintKey = "airomComponentIdentity/v1"
)

// Writer projects an Inventory to SARIF 2.1.0. strict selects the §7.1
// encoding: default emits level "note"; strict emits kind "informational".
type Writer struct{ strict bool }

// New builds a SARIF writer from options. SARIFStrict flips the §7.1
// level/kind encoding globally.
func New(o writer.Options) Writer { return Writer{strict: o.SARIFStrict} }

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
	comps := scannedComponents(inv)
	rules, ruleIndex := buildRules(comps)

	run := sarifRun{
		Tool:        buildTool(inv, rules),
		ColumnKind:  columnKind,
		Invocations: []sarifInvocation{buildInvocation(inv)},
		Results:     wr.buildResults(comps, ruleIndex),
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
// kind except the scan-root application component (§7.3).
func scannedComponents(inv *airom.Inventory) []airom.Component {
	out := make([]airom.Component, 0, len(inv.Components))
	for _, c := range inv.Components {
		if c.Kind == airom.KindApplication || c.ID == inv.Root {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
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

// buildTool assembles tool.driver (§3.1).
func buildTool(inv *airom.Inventory, rules []sarifRule) sarifTool {
	d := sarifDriver{
		Name:            inv.Tool.Name,
		SemanticVersion: inv.Tool.Version,
		InformationURI:  informationURI,
		Rules:           rules,
	}
	if inv.Tool.Commit != "" {
		d.Properties = map[string]any{"airom:tool.commit": inv.Tool.Commit}
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
	if c.Model != nil && c.Model.PickleRisk != nil && len(c.Model.PickleRisk.Globals) > 0 {
		p["airom:pickle.risk"] = "suspicious"
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
