package bench

import (
	"os"
	"strings"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func comp(kind, name, version string) airom.Component {
	c := airom.Component{ID: airom.ID("airom:" + kind + "/" + name), Kind: airom.ComponentKind(kind), Name: name}
	if version != "" {
		c.Version = airom.KnownString(version)
	}
	return c
}

func inv(comps ...airom.Component) *airom.Inventory {
	root := airom.Component{ID: "airom:application/root", Kind: airom.KindApplication, Name: "root"}
	return &airom.Inventory{Root: root.ID, Components: append([]airom.Component{root}, comps...)}
}

// The root application is the scan target, never a detection: it must not
// count as an FP against an empty label set.
func TestRootIsNotReported(t *testing.T) {
	res := Evaluate("r", inv(), &Truth{})
	if res.FP != 0 || res.TP != 0 || res.FN != 0 {
		t.Errorf("empty scan vs empty truth = TP%d FP%d FN%d, want zeros", res.TP, res.FP, res.FN)
	}
}

// Greedy 1:1: one real thing reported twice is one match plus one FP — the
// consumer sees two claims, and the second one is wrong.
func TestSplitBrainIsOneTPOneFP(t *testing.T) {
	i := inv(comp("library", "openai", "1.0"), comp("library", "openai", "2.0"))
	truth := &Truth{Expected: []Label{{Kind: "library", Name: "openai", Version: VersionUngraded}}}
	res := Evaluate("r", i, truth)
	if res.TP != 1 || res.FP != 1 || res.FN != 0 {
		t.Errorf("TP%d FP%d FN%d, want 1/1/0", res.TP, res.FP, res.FN)
	}
}

// version: "" is an assertion of absence; a guessed version is WRONG, not
// generous. version: "*" opts out entirely.
func TestVersionGrading(t *testing.T) {
	i := inv(
		comp("hosted-llm", "gpt-4o", "2024-05-13"), // label asserts absence -> wrong
		comp("library", "openai", "1.2.3"),         // exact
		comp("framework", "langchain", ""),         // label wants 0.3.0 -> missing
		comp("vector-db", "chroma", "9.9"),         // ungraded
	)
	truth := &Truth{Expected: []Label{
		{Kind: "hosted-llm", Name: "gpt-4o", Version: ""},
		{Kind: "library", Name: "openai", Version: "1.2.3"},
		{Kind: "framework", Name: "langchain", Version: "0.3.0"},
		{Kind: "vector-db", Name: "chroma", Version: VersionUngraded},
	}}
	res := Evaluate("r", i, truth)
	v := res.Version
	if v.Wrong != 1 || v.Exact != 1 || v.Missing != 1 || v.Ungraded != 1 || v.AbsentOK != 0 {
		t.Errorf("version grade = %+v", v)
	}
}

// A reported forbidden label is a trap violation AND an ordinary FP: it is a
// wrong claim first, a remembered lesson second.
func TestForbiddenIsTrapAndFP(t *testing.T) {
	i := inv(comp("hosted-llm", "claude-3-opus", ""))
	truth := &Truth{Forbidden: []Label{{Kind: "hosted-llm", Name: "claude-3-opus", Reason: "README table"}}}
	res := Evaluate("r", i, truth)
	if res.FP != 1 {
		t.Errorf("FP = %d, want 1", res.FP)
	}
	if len(res.TrapViolations) != 1 || !strings.Contains(res.TrapViolations[0], "README table") {
		t.Errorf("traps = %v", res.TrapViolations)
	}
}

// Name matching folds case and separator churn, and nothing else.
func TestNormalization(t *testing.T) {
	i := inv(comp("library", "Sentence_Transformers", ""))
	truth := &Truth{Expected: []Label{{Kind: "library", Name: "sentence-transformers", Version: VersionUngraded}}}
	if res := Evaluate("r", i, truth); res.TP != 1 {
		t.Errorf("normalized match failed: %+v", res)
	}
}

// scope: test labels match only test-scoped components, and test-scoped
// components never satisfy default labels — the corpus grades what the
// default presentation shows.
func TestScopePools(t *testing.T) {
	testComp := comp("library", "openai", "")
	testComp.TestOnly = true
	i := inv(testComp)
	def := &Truth{Expected: []Label{{Kind: "library", Name: "openai", Version: VersionUngraded}}}
	if res := Evaluate("r", i, def); res.TP != 0 || res.FN != 1 {
		t.Errorf("default label matched a test-only component: %+v", res)
	}
	scoped := &Truth{Expected: []Label{{Kind: "library", Name: "openai", Scope: "test", Version: VersionUngraded}}}
	if res := Evaluate("r", i, scoped); res.TP != 1 {
		t.Errorf("scope:test label failed to match: %+v", res)
	}
}

func TestTruthValidation(t *testing.T) {
	for name, yaml := range map[string]string{
		"unknown kind":            "schemaVersion: 1\nlabeler: x\nexpected:\n  - {kind: nonsense, name: a}\n",
		"missing labeler":         "schemaVersion: 1\nexpected:\n  - {kind: library, name: a}\n",
		"forbidden needs reason":  "schemaVersion: 1\nlabeler: x\nforbidden:\n  - {kind: library, name: a}\n",
		"scan args reserved":      "schemaVersion: 1\nlabeler: x\nscan: {args: [--wide]}\n",
		"wrong schema":            "schemaVersion: 2\nlabeler: x\n",
		"typo'd key fails loudly": "schemaVersion: 1\nlabeler: x\nexpceted:\n  - {kind: library, name: a}\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := dir + "/truth.yaml"
			if err := writeFile(p, yaml); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadTruth(p); err == nil {
				t.Errorf("%s: accepted", name)
			}
		})
	}
}

func TestCompareGate(t *testing.T) {
	base := Aggregate("v1", "", "", []*RepoResult{{
		Repo: "a", TP: 90, FP: 5, FN: 10,
		PerKind: map[string]*PRCell{"library": {TP: 30, FP: 1, FN: 2}},
		PerLang: map[string]*PRCell{}, Bands: map[string]*BandCell{},
	}})

	t.Run("precision drop fails", func(t *testing.T) {
		cur := Aggregate("v2", "", "", []*RepoResult{{
			Repo: "a", TP: 90, FP: 12, FN: 10,
			PerKind: map[string]*PRCell{}, PerLang: map[string]*PRCell{}, Bands: map[string]*BandCell{},
		}})
		fails, _ := Compare(base, cur)
		if len(fails) == 0 {
			t.Error("a 5-point precision drop passed the gate")
		}
	})
	t.Run("improvement is a remark, not a failure", func(t *testing.T) {
		cur := Aggregate("v2", "", "", []*RepoResult{{
			Repo: "a", TP: 98, FP: 1, FN: 2,
			PerKind: map[string]*PRCell{}, PerLang: map[string]*PRCell{}, Bands: map[string]*BandCell{},
		}})
		fails, remarks := Compare(base, cur)
		if len(fails) != 0 {
			t.Errorf("improvement failed the gate: %v", fails)
		}
		if len(remarks) == 0 {
			t.Error("improvement produced no baseline-update remark")
		}
	})
	t.Run("wrong versions gate with no threshold", func(t *testing.T) {
		cur := Aggregate("v2", "", "", []*RepoResult{{
			Repo: "a", TP: 90, FP: 5, FN: 10, Version: AttrGrade{Wrong: 1},
			PerKind: map[string]*PRCell{}, PerLang: map[string]*PRCell{}, Bands: map[string]*BandCell{},
		}})
		fails, _ := Compare(base, cur)
		if len(fails) == 0 {
			t.Error("a new wrong version passed the gate")
		}
	})
	t.Run("thin kinds are exempt", func(t *testing.T) {
		thin := Aggregate("v1", "", "", []*RepoResult{{
			Repo: "a", TP: 5, FP: 0, FN: 0,
			PerKind: map[string]*PRCell{"prompt": {TP: 5, FP: 0, FN: 0}},
			PerLang: map[string]*PRCell{}, Bands: map[string]*BandCell{},
		}})
		cur := Aggregate("v2", "", "", []*RepoResult{{
			Repo: "a", TP: 5, FP: 1, FN: 0,
			PerKind: map[string]*PRCell{"prompt": {TP: 5, FP: 1, FN: 0}},
			PerLang: map[string]*PRCell{}, Bands: map[string]*BandCell{},
		}})
		fails, _ := Compare(thin, cur)
		for _, f := range fails {
			if strings.HasPrefix(f, "kind ") {
				t.Errorf("per-kind gate fired below the %d-label floor: %s", kindFloor, f)
			}
		}
	})
}

func writeFile(p, body string) error {
	return os.WriteFile(p, []byte(body), 0o644)
}
