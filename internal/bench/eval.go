package bench

import (
	"path"
	"sort"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
)

// RepoResult is the metric set for one corpus entry. Every rate the report
// derives from it is printed next to these counts.
type RepoResult struct {
	Repo string `json:"repo"`

	TP int `json:"tp"` // matched (label found)
	FP int `json:"fp"` // reported, no label
	FN int `json:"fn"` // labeled, not reported

	PerKind map[string]*PRCell `json:"perKind"`
	PerLang map[string]*PRCell `json:"perLang"`

	// Attribute grades over matched components (docs/benchmark.md §4:
	// attributes are graded, not matched on).
	Version  AttrGrade `json:"version"`
	Provider AttrGrade `json:"provider"`
	Location LocGrade  `json:"location"`

	// Traps: forbidden labels that were reported anyway. Each is also an FP;
	// the class is separate because each trap encodes a lesson already
	// learned once.
	TrapViolations []string `json:"trapViolations,omitempty"`

	// Coverage, straight off the assurance block.
	FilesProcessed int64 `json:"filesProcessed"`
	Unknowns       int   `json:"unknowns"`
	FilesTruncated int64 `json:"filesTruncated"`

	// Bands feed the calibration study: per confidence band, how many
	// reported components and how many of them were correct (= matched).
	Bands map[string]*BandCell `json:"bands"`
}

// PRCell is one precision/recall cell: reported, matched, labeled.
type PRCell struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
}

// AttrGrade buckets an attribute over matched components. Wrong is the bucket
// the gate watches: a wrong claim outranks a missing one everywhere in AIROM,
// and the benchmark grades by the same rule.
type AttrGrade struct {
	Exact    int `json:"exact"`    // label states it, report agrees
	AbsentOK int `json:"absentOk"` // label asserts absence, report is absent
	Missing  int `json:"missing"`  // label states it, report omits it
	Wrong    int `json:"wrong"`    // report contradicts the label
	Ungraded int `json:"ungraded"` // label opted out
}

// LocGrade buckets evidence-location validity over matched components.
type LocGrade struct {
	Valid    int `json:"valid"`    // an occurrence lands on labeled evidence
	Invalid  int `json:"invalid"`  // no occurrence does
	Ungraded int `json:"ungraded"` // label carries no evidence
}

// BandCell is one confidence band's calibration sample.
type BandCell struct {
	N       int `json:"n"`
	Correct int `json:"correct"`
}

// Evaluate grades one scan against one truth. Pure: no I/O, deterministic.
func Evaluate(repo string, inv *airom.Inventory, truth *Truth) *RepoResult {
	res := &RepoResult{
		Repo:           repo,
		PerKind:        map[string]*PRCell{},
		PerLang:        map[string]*PRCell{},
		Bands:          map[string]*BandCell{},
		FilesProcessed: inv.Stats.FilesProcessed,
		Unknowns:       len(inv.Unknowns),
		FilesTruncated: inv.Stats.FilesTruncated,
	}

	// The reported set: what a user of the default presentation sees. The
	// root application is the scan target, not a detection. Test-scoped
	// components are matched only by scope:test labels, mirroring how the
	// default table hides them.
	var def, test []*airom.Component
	for i := range inv.Components {
		c := &inv.Components[i]
		if c.ID == inv.Root {
			continue
		}
		if c.TestOnly {
			test = append(test, c)
		} else {
			def = append(def, c)
		}
	}
	sortComponents(def)
	sortComponents(test)

	matched := map[*airom.Component]*Label{}
	claimed := map[*airom.Component]bool{}

	// Greedy 1:1 on (kind, normalized name), labels in file order: the
	// labeler's order is part of the contract, and stability beats cleverness.
	for i := range truth.Expected {
		l := &truth.Expected[i]
		pool := def
		if l.Scope == "test" {
			pool = test
		}
		var hit *airom.Component
		for _, c := range pool {
			if !claimed[c] && string(c.Kind) == l.Kind && NormalizeName(c.Name) == NormalizeName(l.Name) {
				hit = c
				break
			}
		}
		if hit == nil {
			res.FN++
			cell(res.PerKind, l.Kind).FN++
			cell(res.PerLang, labelLang(l)).FN++
			continue
		}
		claimed[hit] = true
		matched[hit] = l
		res.TP++
		cell(res.PerKind, l.Kind).TP++
		cell(res.PerLang, labelLang(l)).TP++
		gradeAttrs(res, hit, l)
	}

	// Everything reported and unclaimed is a false positive; a forbidden
	// match is additionally a trap violation.
	for _, c := range def {
		band := c.Confidence.Band()
		b := bandCell(res.Bands, band)
		b.N++
		if claimed[c] {
			b.Correct++
			continue
		}
		res.FP++
		cell(res.PerKind, string(c.Kind)).FP++
		cell(res.PerLang, componentLang(c)).FP++
		for i := range truth.Forbidden {
			f := &truth.Forbidden[i]
			if string(c.Kind) == f.Kind && NormalizeName(c.Name) == NormalizeName(f.Name) {
				res.TrapViolations = append(res.TrapViolations,
					f.Kind+"/"+f.Name+": "+f.Reason)
				break
			}
		}
	}
	sort.Strings(res.TrapViolations)
	return res
}

func gradeAttrs(res *RepoResult, c *airom.Component, l *Label) {
	// Version: "" asserts absence; "*" opts out.
	got, known := c.Version.Value()
	switch {
	case l.Version == VersionUngraded:
		res.Version.Ungraded++
	case l.Version == "" && !known:
		res.Version.AbsentOK++
	case l.Version == "" && known:
		res.Version.Wrong++ // a guessed version where none is knowable
	case !known:
		res.Version.Missing++
	case got == l.Version:
		res.Version.Exact++
	default:
		res.Version.Wrong++
	}

	prov, provKnown := c.Provider.Value()
	switch {
	case l.Provider == "":
		res.Provider.Ungraded++
	case !provKnown:
		res.Provider.Missing++
	case NormalizeName(prov) == NormalizeName(l.Provider):
		res.Provider.Exact++
	default:
		res.Provider.Wrong++
	}

	if len(l.Evidence) == 0 {
		res.Location.Ungraded++
		return
	}
	for _, occ := range c.Evidence.Occurrences {
		for _, ev := range l.Evidence {
			if occ.Location.Path != ev.File {
				continue
			}
			if len(ev.Lines) == 0 ||
				(occ.Location.Line >= ev.Lines[0] && occ.Location.Line <= ev.Lines[1]) {
				res.Location.Valid++
				return
			}
		}
	}
	res.Location.Invalid++
}

func cell(m map[string]*PRCell, k string) *PRCell {
	if m[k] == nil {
		m[k] = &PRCell{}
	}
	return m[k]
}

func bandCell(m map[string]*BandCell, k string) *BandCell {
	if m[k] == nil {
		m[k] = &BandCell{}
	}
	return m[k]
}

func sortComponents(cs []*airom.Component) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
}

// extLang maps evidence-file extensions onto the rule engine's language set.
// Manifests and model binaries get their own buckets: "the Python rules are
// healthy" and "the requirements.txt parser is healthy" are different claims.
var extLang = map[string]string{
	".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
	".ts": "typescript", ".tsx": "typescript", ".go": "go", ".java": "java",
	".rs": "rust", ".cs": "csharp", ".kt": "kotlin", ".kts": "kotlin", ".sql": "sql",
}

func fileLang(p string) string {
	if l, ok := extLang[strings.ToLower(path.Ext(p))]; ok {
		return l
	}
	base := strings.ToLower(path.Base(p))
	switch {
	case strings.Contains(base, "requirements") || base == "pyproject.toml" ||
		base == "package.json" || base == "go.mod" || base == "cargo.toml" ||
		base == "pom.xml" || strings.HasSuffix(base, ".csproj") ||
		strings.HasPrefix(base, "build.gradle") || strings.HasSuffix(base, ".lock") ||
		strings.HasSuffix(base, "-lock.json") || strings.HasSuffix(base, "-lock.yaml"):
		return "manifest"
	case strings.HasSuffix(base, ".gguf") || strings.HasSuffix(base, ".safetensors") ||
		strings.HasSuffix(base, ".onnx") || strings.HasSuffix(base, ".pt") ||
		strings.HasSuffix(base, ".pth") || strings.HasSuffix(base, ".bin") ||
		strings.HasSuffix(base, ".h5") || strings.HasSuffix(base, ".tflite"):
		return "model-file"
	}
	return "other"
}

func labelLang(l *Label) string {
	if len(l.Evidence) > 0 {
		return fileLang(l.Evidence[0].File)
	}
	return "other"
}

func componentLang(c *airom.Component) string {
	if len(c.Evidence.Occurrences) > 0 {
		return fileLang(c.Evidence.Occurrences[0].Location.Path)
	}
	return "other"
}
