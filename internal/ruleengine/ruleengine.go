// Package ruleengine implements the declarative rule-pack compiler and the
// generic rule detector (ARCHITECTURE.md §6.3, docs/rule-schema.md — this
// package implements exactly that contract). Rule packs are the data half
// of the hybrid detection strategy: keywords + regex over classified text
// regions + a templated claim. Packs are parsed and validated once at
// startup (fail-fast, gitleaks lineage), merged across layers by rule ID,
// compiled into one Aho–Corasick-prefiltered matcher, and executed by a
// single FileDetector.
package ruleengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// ── Schema (docs/rule-schema.md) ────────────────────────────────────────────

// Pack is one YAML rule-pack file.
type Pack struct {
	Pack    string `yaml:"pack" json:"pack"`
	Version int    `yaml:"version" json:"version"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}

// Rule is one declarative detection.
type Rule struct {
	ID            string         `yaml:"id" json:"id"`
	Kind          string         `yaml:"kind" json:"kind"`
	Provider      string         `yaml:"provider" json:"provider,omitempty"`
	Languages     []string       `yaml:"languages" json:"languages,omitempty"`
	Keywords      []string       `yaml:"keywords" json:"keywords"`
	Pattern       string         `yaml:"pattern" json:"pattern"`
	Regions       []string       `yaml:"regions" json:"regions,omitempty"`
	Claim         ClaimTmpl      `yaml:"claim" json:"claim"`
	Relations     []RelationTmpl `yaml:"relations" json:"relations,omitempty"`
	CaptureParams *CaptureParams `yaml:"capture_params" json:"captureParams,omitempty"`
	Confidence    float64        `yaml:"confidence" json:"confidence"`
	Disable       bool           `yaml:"disable" json:"disable,omitempty"` // overlay only
}

// ClaimTmpl is the templated component claim (${group} substitution).
type ClaimTmpl struct {
	Name    string `yaml:"name" json:"name"`
	Group   string `yaml:"group" json:"group,omitempty"`
	Version string `yaml:"version" json:"version,omitempty"`
}

// RelationTmpl is a templated relationship claim.
type RelationTmpl struct {
	Type   string     `yaml:"type" json:"type"`
	Target TargetTmpl `yaml:"target" json:"target"`
}

// TargetTmpl is a relation target hint: exactly one form set (lint rule 7).
type TargetTmpl struct {
	Kind      string `yaml:"kind" json:"kind,omitempty"`
	Name      string `yaml:"name" json:"name,omitempty"`
	FromField string `yaml:"from_field" json:"fromField,omitempty"`
	LocalRef  string `yaml:"local_ref" json:"localRef,omitempty"`
}

// CaptureParams is same-call-site generation-parameter capture (§9.5).
type CaptureParams struct {
	WithinLines int      `yaml:"within_lines" json:"withinLines"`
	Names       []string `yaml:"names" json:"names"`
}

// ruleExpressibleKinds per docs/rule-schema.md: local-model-file,
// rag-pipeline, and application are structurally reserved for Go detectors
// and the assembler.
var ruleExpressibleKinds = map[string]airom.ComponentKind{
	"hosted-llm":      airom.KindHostedLLM,
	"embedding-model": airom.KindEmbeddingModel,
	"framework":       airom.KindFramework,
	"library":         airom.KindLibrary,
	"vector-db":       airom.KindVectorDB,
	"prompt":          airom.KindPrompt,
	"dataset":         airom.KindDataset,
	"ai-config":       airom.KindAIConfig,
	"infra":           airom.KindInfra,
	"service":         airom.KindService,
}

var supportedLanguages = map[string]detect.Language{
	"python":     detect.LangPython,
	"javascript": detect.LangJavaScript,
	"typescript": detect.LangTypeScript,
	"go":         detect.LangGo,
	"java":       detect.LangJava,
	"rust":       detect.LangRust,
	"csharp":     detect.LangCSharp,
	"kotlin":     detect.LangKotlin,
}

var relTypes = map[string]airom.RelType{
	"uses": airom.RelUses, "depends-on": airom.RelDependsOn,
	"served-by": airom.RelServedBy, "queries": airom.RelQueries,
	"embeds-with": airom.RelEmbedsWith, "prompted-by": airom.RelPromptedBy,
	"trained-on": airom.RelTrainedOn, "derived-from": airom.RelDerivedFrom,
	"configures": airom.RelConfigures, "contains": airom.RelContains,
}

var (
	packNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)
	ruleIDRe   = regexp.MustCompile(`^[a-z0-9-]+/[a-z0-9/-]+$`)
	templateRe = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)
)

// ── Loading and layering ────────────────────────────────────────────────────

// EffectiveRule is a post-merge rule with its originating layer recorded
// (`airom rules list` shows it).
type EffectiveRule struct {
	Rule
	Layer string // "embedded" or the overlay file path
}

// Ruleset is the merged, validated, effective rule collection.
type Ruleset struct {
	Rules []EffectiveRule // sorted by ID
	// Hash is the SHA-256 of the canonical serialization of the effective
	// ruleset — the self-invalidating cache-namespace ingredient
	// (docs/rule-schema.md "Cache keys").
	Hash string
}

// ParsePack strictly parses one pack file. stem is the filename stem for
// the pack-name check ("" skips it, for tests).
func ParsePack(stem string, data []byte) (Pack, error) {
	var p Pack
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Pack{}, fmt.Errorf("parse: %w", err)
	}
	if !packNameRe.MatchString(p.Pack) {
		return Pack{}, fmt.Errorf("pack %q: must match [a-z0-9-]+", p.Pack)
	}
	if stem != "" && p.Pack != stem {
		return Pack{}, fmt.Errorf("pack %q: must equal the filename stem %q", p.Pack, stem)
	}
	if p.Version < 1 {
		return Pack{}, fmt.Errorf("pack %q: version must be >= 1", p.Pack)
	}
	if len(p.Rules) == 0 {
		return Pack{}, fmt.Errorf("pack %q: at least one rule required", p.Pack)
	}
	return p, nil
}

// Load assembles the effective ruleset from the embedded layer (nil-able
// fs.FS holding <category>/<pack>.yaml) plus overlay files in flag order,
// applying the documented merge semantics (add / override / disable by rule
// ID; later layers win) and the full startup lint contract.
func Load(embedded fs.FS, overlayPaths []string, readFile func(string) ([]byte, error)) (*Ruleset, error) {
	effective := map[string]EffectiveRule{}

	if embedded != nil {
		var paths []string
		err := fs.WalkDir(embedded, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".yaml") {
				paths = append(paths, p)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk embedded rules: %w", err)
		}
		sort.Strings(paths)
		for _, p := range paths {
			data, err := fs.ReadFile(embedded, p)
			if err != nil {
				return nil, fmt.Errorf("read embedded %s: %w", p, err)
			}
			pack, err := ParsePack(stem(p), data)
			if err != nil {
				return nil, fmt.Errorf("embedded %s: %w", p, err)
			}
			if err := applyLayer(effective, pack, "embedded", true); err != nil {
				return nil, fmt.Errorf("embedded %s: %w", p, err)
			}
		}
	}

	for _, p := range overlayPaths {
		data, err := readFile(p)
		if err != nil {
			return nil, fmt.Errorf("--rules %s: %w", p, err)
		}
		pack, err := ParsePack("", data) // overlays: stem check not enforced
		if err != nil {
			return nil, fmt.Errorf("--rules %s: %w", p, err)
		}
		if err := applyLayer(effective, pack, p, false); err != nil {
			return nil, fmt.Errorf("--rules %s: %w", p, err)
		}
	}

	rs := &Ruleset{}
	for _, r := range effective {
		rs.Rules = append(rs.Rules, r)
	}
	sort.Slice(rs.Rules, func(i, j int) bool { return rs.Rules[i].ID < rs.Rules[j].ID })

	for _, r := range rs.Rules {
		if err := validateRule(r.Rule); err != nil {
			return nil, fmt.Errorf("rule %q (%s): %w", r.ID, r.Layer, err)
		}
	}

	canonical, err := json.Marshal(rulesOnly(rs.Rules))
	if err != nil {
		return nil, fmt.Errorf("hash ruleset: %w", err)
	}
	sum := sha256.Sum256(canonical)
	rs.Hash = hex.EncodeToString(sum[:])
	return rs, nil
}

func rulesOnly(effective []EffectiveRule) []Rule {
	out := make([]Rule, len(effective))
	for i, r := range effective {
		out[i] = r.Rule
	}
	return out
}

func stem(p string) string {
	return strings.TrimSuffix(path.Base(p), path.Ext(p))
}

// applyLayer merges one pack into the effective set. base layers may not
// collide with themselves; overlays add (namespaced by their own pack name),
// override wholly, or disable.
func applyLayer(effective map[string]EffectiveRule, pack Pack, layer string, base bool) error {
	for _, r := range pack.Rules {
		if !ruleIDRe.MatchString(r.ID) {
			return fmt.Errorf("rule id %q: must match <pack>/<slug> in [a-z0-9-/]", r.ID)
		}
		_, exists := effective[r.ID]

		if r.Disable {
			if base {
				return fmt.Errorf("rule %q: disable is overlay-only", r.ID)
			}
			if !exists {
				return fmt.Errorf("rule %q: disable target does not exist", r.ID)
			}
			delete(effective, r.ID)
			continue
		}

		if base {
			if exists {
				return fmt.Errorf("rule %q: duplicate ID within the embedded layer", r.ID)
			}
			if prefix := strings.SplitN(r.ID, "/", 2)[0]; prefix != pack.Pack {
				return fmt.Errorf("rule %q: id prefix must equal pack %q", r.ID, pack.Pack)
			}
		} else if !exists {
			// Overlay ADD: new IDs must be namespaced by the overlay pack.
			if prefix := strings.SplitN(r.ID, "/", 2)[0]; prefix != pack.Pack {
				return fmt.Errorf("rule %q: new overlay rule must be namespaced by its own pack %q", r.ID, pack.Pack)
			}
		}
		effective[r.ID] = EffectiveRule{Rule: r, Layer: layer}
	}
	return nil
}

// validateRule enforces the startup lint contract (docs/rule-schema.md,
// items 2–9; fixture checks are `airom rules lint`'s job).
func validateRule(r Rule) error {
	if _, ok := ruleExpressibleKinds[r.Kind]; !ok {
		return fmt.Errorf("kind %q is not rule-expressible", r.Kind)
	}
	for _, l := range r.Languages {
		if _, ok := supportedLanguages[l]; !ok {
			return fmt.Errorf("unsupported language %q", l)
		}
	}
	if len(r.Keywords) == 0 {
		return fmt.Errorf("keywords is mandatory and non-empty (un-prefiltered regexes cannot ship)")
	}
	for _, k := range r.Keywords {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("empty keyword")
		}
	}
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return fmt.Errorf("pattern does not compile: %w", err)
	}
	for _, region := range r.Regions {
		if region != "code" && region != "string" {
			return fmt.Errorf("regions must be a subset of [code, string], got %q", region)
		}
	}
	if !(r.Confidence > 0 && r.Confidence <= 0.99) {
		return fmt.Errorf("confidence must be in (0, 0.99], got %v", r.Confidence)
	}
	if r.Claim.Name == "" {
		return fmt.Errorf("claim.name is required")
	}

	// Named-group / template cross-referencing (lint rule 5).
	groups := map[string]bool{}
	for _, g := range re.SubexpNames() {
		if g != "" {
			groups[g] = true
		}
	}
	captureNames := map[string]bool{}
	if r.CaptureParams != nil {
		if r.CaptureParams.WithinLines < 1 || r.CaptureParams.WithinLines > 64 {
			return fmt.Errorf("capture_params.within_lines must be in [1, 64]")
		}
		if len(r.CaptureParams.Names) == 0 {
			return fmt.Errorf("capture_params.names must be non-empty")
		}
		for _, n := range r.CaptureParams.Names {
			captureNames[n] = true
		}
	}

	referenced := map[string]bool{"model": true} // semantically consumed by §9.5
	checkTemplate := func(tmpl, where string) error {
		for _, m := range templateRe.FindAllStringSubmatch(tmpl, -1) {
			if !groups[m[1]] {
				return fmt.Errorf("%s references ${%s}, which is not a named group", where, m[1])
			}
			referenced[m[1]] = true
		}
		return nil
	}
	if err := checkTemplate(r.Claim.Name, "claim.name"); err != nil {
		return err
	}
	if err := checkTemplate(r.Claim.Group, "claim.group"); err != nil {
		return err
	}
	if err := checkTemplate(r.Claim.Version, "claim.version"); err != nil {
		return err
	}

	for i, rel := range r.Relations {
		if _, ok := relTypes[rel.Type]; !ok {
			return fmt.Errorf("relations[%d]: unknown type %q", i, rel.Type)
		}
		forms := 0
		if rel.Target.Name != "" {
			forms++
			if err := checkTemplate(rel.Target.Name, fmt.Sprintf("relations[%d].target.name", i)); err != nil {
				return err
			}
		}
		if rel.Target.FromField != "" {
			forms++
			// "model" is implicitly captured in the capture_params window
			// (§9.5: the canonical same-call-site binding) — so a rule with
			// capture_params may reference it without declaring it.
			implicitModel := rel.Target.FromField == "model" && r.CaptureParams != nil
			if !groups[rel.Target.FromField] && !captureNames[rel.Target.FromField] && !implicitModel {
				return fmt.Errorf("relations[%d].target.from_field %q references no named group or capture_params name", i, rel.Target.FromField)
			}
			referenced[rel.Target.FromField] = true
		}
		if rel.Target.LocalRef != "" {
			forms++
		}
		if forms != 1 {
			return fmt.Errorf("relations[%d].target must set exactly one of name, from_field, local_ref", i)
		}
		if (rel.Target.Name != "" || rel.Target.FromField != "") && rel.Target.Kind == "" {
			return fmt.Errorf("relations[%d].target needs a kind", i)
		}
		if rel.Target.Kind != "" {
			if _, ok := ruleExpressibleKinds[rel.Target.Kind]; !ok {
				return fmt.Errorf("relations[%d].target.kind %q is not rule-expressible", i, rel.Target.Kind)
			}
		}
	}

	for g := range groups {
		if !referenced[g] {
			return fmt.Errorf("named group %q is never referenced (dead weight or a typo)", g)
		}
	}
	return nil
}
