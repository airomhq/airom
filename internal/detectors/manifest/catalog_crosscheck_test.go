package manifest

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/airomhq/airom/internal/assemble"
	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

// TestCatalogAgreesWithRulePacks is the guard for a defect class that is
// invisible in any single test: the manifest catalog and the rule packs
// describing the SAME dependency disagreeing about its provider or its kind.
//
// The two halves are written in different files, in different languages, by
// different changes — a catalog entry in Go, a rule pack in YAML — and nothing
// forced them to agree. When they disagree on provider, the assembler cannot
// fold them, so `openai==1.2.3` in requirements.txt and `import openai` in the
// code are reported as TWO components: one with a version and no evidence of
// use, one with usage and no version. When they disagree on kind, whichever
// sighting wins decides whether the dependency is a "framework" or a
// "library", so the answer changes with the contents of the repo.
//
// The check is behavioral rather than a table comparison: each pair is run
// through the real assembler, so it exercises the actual normalization —
// PEP 503 names, nameAliases, providerAliases — instead of a second copy of
// those rules that could drift from the first.
func TestCatalogAgreesWithRulePacks(t *testing.T) {
	rules := loadRuleClaims(t)
	if len(rules) == 0 {
		t.Fatal("no rule claims parsed — the cross-check would pass vacuously")
	}

	// Index rules by the canonical name the assembler gives them. A pack
	// usually declares the same claim on several rules (import, construct);
	// they are one opinion, so collapse them or every mismatch reports twice.
	byName := map[string][]ruleClaim{}
	seen := map[ruleClaim]bool{}
	for _, r := range rules {
		if seen[r] {
			continue
		}
		seen[r] = true
		n := canonicalName(t, r.finding())
		byName[n] = append(byName[n], r)
	}

	for _, e := range catalogEntries() {
		mf := e.finding()
		name := canonicalName(t, mf)
		for _, r := range byName[name] {
			if classOfKind(r.kind) != classOfKind(e.pkg.kind) {
				continue // different component families; not the same asset
			}
			t.Run(e.ecosystem+"/"+e.key+" vs "+r.pack, func(t *testing.T) {
				inv := assemble.Build([]detect.Finding{mf, r.finding()}, nil, airom.ScanStats{}, assemble.Options{})
				got := packageComponents(inv)
				if len(got) == 1 {
					return
				}
				var lines []string
				for _, c := range got {
					prov, _ := c.Provider.Value()
					lines = append(lines, "    "+string(c.Kind)+" "+c.Name+" provider="+quoteOrDash(prov))
				}
				sort.Strings(lines)
				t.Errorf(
					"catalog %q and rule pack %q describe %q but do not fold into one component:\n%s\n"+
						"  catalog: kind=%s provider=%q  (internal/detectors/manifest/catalog.go)\n"+
						"  rules:   kind=%s provider=%q  (rules/.../%s.yaml)\n"+
						"  Fix whichever is wrong so both name the same vendor and the same kind.",
					e.key, r.pack, name, strings.Join(lines, "\n"),
					e.pkg.kind, e.pkg.provider, r.kind, r.provider, r.pack,
				)
			})
		}
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

type catEntry struct {
	ecosystem string
	key       string
	pkg       aiPkg
}

func (e catEntry) finding() detect.Finding {
	f := mkFinding(e.pkg, e.pkg.emitName(e.key), "", e.ecosystem, "1.0.0", 1)
	f.Occurrence.Location.Path = "manifest"
	f.Occurrence.DetectorID = "manifest/x"
	return f
}

// catalogEntries flattens every ecosystem table into one list.
func catalogEntries() []catEntry {
	tables := []struct {
		ecosystem string
		c         catalog
	}{
		{"pypi", pypiCatalog},
		{"npm", npmCatalog},
		{"golang", goCatalog},
		{"cargo", cargoCatalog},
	}
	var out []catEntry
	for _, tb := range tables {
		for key, p := range tb.c.exact {
			out = append(out, catEntry{tb.ecosystem, key, p})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ecosystem != out[j].ecosystem {
			return out[i].ecosystem < out[j].ecosystem
		}
		return out[i].key < out[j].key
	})
	return out
}

type ruleClaim struct {
	pack     string
	name     string
	kind     airom.ComponentKind
	provider string
}

func (r ruleClaim) finding() detect.Finding {
	return detect.Finding{
		Claim: detect.ComponentClaim{
			Kind:     r.kind,
			Name:     r.name,
			Provider: r.provider,
			Package:  &detect.PackageClaim{},
		},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Path: "src/app.py", Line: 1},
			DetectorID: "rules/" + r.pack,
			Method:     airom.MethodSourceCode,
			Confidence: 0.7,
		},
	}
}

var (
	reRuleID   = regexp.MustCompile(`(?m)^\s*-\s+id:\s*(\S+)`)
	reKind     = regexp.MustCompile(`(?m)^\s*kind:\s*(\S+)`)
	reProvider = regexp.MustCompile(`(?m)^\s*provider:\s*(\S+)`)
	reName     = regexp.MustCompile(`name:\s*"([^"]+)"`)
)

// loadRuleClaims reads the embedded rule packs and returns one entry per rule
// that names a fixed component (templated names like "${model}" are a model
// id, not a package, and have no catalog counterpart).
func loadRuleClaims(t *testing.T) []ruleClaim {
	t.Helper()
	root := filepath.Join("..", "..", "..", "rules")
	var out []ruleClaim
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		data, err := os.ReadFile(p) // #nosec G304 -- the repo's own rule packs
		if err != nil {
			return err
		}
		pack := strings.TrimSuffix(filepath.Base(p), ".yaml")
		// Split on rule boundaries so each rule's fields stay together.
		body := string(data)
		idx := reRuleID.FindAllStringIndex(body, -1)
		for i, loc := range idx {
			end := len(body)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			block := body[loc[0]:end]
			nm := reName.FindStringSubmatch(block)
			kd := reKind.FindStringSubmatch(block)
			if nm == nil || kd == nil || strings.Contains(nm[1], "${") {
				continue
			}
			prov := ""
			if m := reProvider.FindStringSubmatch(block); m != nil {
				prov = m[1]
			}
			out = append(out, ruleClaim{pack: pack, name: nm[1], kind: airom.ComponentKind(kd[1]), provider: prov})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk rule packs: %v", err)
	}
	return out
}

// canonicalName runs one finding through the assembler and reports the name it
// settles on — the same normalization the real pipeline applies.
func canonicalName(t *testing.T, f detect.Finding) string {
	t.Helper()
	for _, c := range packageComponents(assemble.Build([]detect.Finding{f}, nil, airom.ScanStats{}, assemble.Options{})) {
		return c.Name
	}
	return ""
}

// packageComponents returns the framework/library/vector-db components, i.e.
// everything except the synthetic application root.
func packageComponents(inv *airom.Inventory) []airom.Component {
	var out []airom.Component
	for _, c := range inv.Components {
		switch c.Kind {
		case airom.KindFramework, airom.KindLibrary, airom.KindVectorDB:
			out = append(out, c)
		}
	}
	return out
}

// classOfKind mirrors the assembler's component families closely enough to
// tell "same asset, different opinion" from "genuinely different things".
func classOfKind(k airom.ComponentKind) string {
	if k == airom.KindVectorDB {
		return "vecdb"
	}
	return "package"
}

func quoteOrDash(s string) string {
	if s == "" {
		return "(none)"
	}
	return `"` + s + `"`
}
