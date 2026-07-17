package ruleengine

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// openaiPack is the canonical worked example from docs/rule-schema.md.
const openaiPack = `
pack: openai
version: 4
rules:
  - id: openai/model-literal
    kind: hosted-llm
    provider: openai
    languages: [python, javascript, typescript, go, java, rust, csharp, kotlin]
    keywords: ["gpt-", "o3", "o4-", "chatgpt-"]
    pattern: '\bmodel\s*[:=]\s*["''](?P<model>gpt-[\w.\-]+|o[34][\w.\-]*)["'']'
    regions: [code, string]
    claim: { name: "${model}" }
    confidence: 0.85

  - id: openai/chat-call
    kind: library
    provider: openai
    keywords: ["chat.completions.create", "responses.create"]
    pattern: '\.(chat\.completions|responses)\.create\s*\('
    claim: { name: "openai-sdk" }
    relations:
      - { type: uses, target: { kind: hosted-llm, from_field: model } }
    capture_params:
      within_lines: 12
      names: [temperature, top_p, top_k, max_tokens, max_output_tokens, seed,
              stop, reasoning_effort, response_format]
    confidence: 0.7
`

const pythonFixture = `import openai

client = openai.OpenAI()

# model = "gpt-4.1-in-a-comment" must NOT match (comments are never scanned)
def ask(q):
    resp = client.chat.completions.create(
        model="gpt-4.1",
        temperature=0.2,
        max_tokens=512,
        messages=[{"role": "user", "content": q}],
    )
    return resp
`

func loadTestPack(t *testing.T, yaml string) *Matcher {
	t.Helper()
	rs, err := Load(nil, []string{"test.yaml"}, func(string) ([]byte, error) { return []byte(yaml), nil })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return m
}

func detectOn(t *testing.T, m *Matcher, path, content string) []detect.Finding {
	t.Helper()
	d := NewDetector(m)
	f := detect.NewFile(detect.FileRef{
		Path:     path,
		Size:     int64(len(content)),
		Language: detect.LanguageOf(path),
	}, []byte(content), detect.FileProviders{
		Content: func() ([]byte, bool, error) { return []byte(content), false, nil },
	})
	findings, err := d.DetectFile(context.Background(), f)
	if err != nil {
		t.Fatalf("DetectFile: %v", err)
	}
	return findings
}

// TestEndToEnd exercises the full flow on the canonical pack: parse →
// validate → compile → lex → prefilter → match → template → capture.
func TestEndToEnd(t *testing.T) {
	m := loadTestPack(t, openaiPack)
	findings := detectOn(t, m, "app.py", pythonFixture)

	var model, call *detect.Finding
	for i := range findings {
		switch findings[i].Occurrence.DetectorID {
		case "rules/openai/model-literal":
			model = &findings[i]
		case "rules/openai/chat-call":
			call = &findings[i]
		}
	}

	if model == nil {
		t.Fatalf("model-literal did not fire; findings: %+v", findings)
	}
	if model.Claim.Name != "gpt-4.1" {
		t.Errorf("claim name = %q, want gpt-4.1 (template expansion)", model.Claim.Name)
	}
	if model.Claim.Kind != airom.KindHostedLLM || model.Claim.Provider != "openai" {
		t.Errorf("claim kind/provider = %v/%v", model.Claim.Kind, model.Claim.Provider)
	}
	if model.Occurrence.Location.Line != 8 {
		t.Errorf("model line = %d, want 8 (1-based)", model.Occurrence.Location.Line)
	}
	if model.Occurrence.Method != airom.MethodSourceCode {
		t.Errorf("method = %v", model.Occurrence.Method)
	}
	if model.Occurrence.Fields["model"] != "gpt-4.1" {
		t.Errorf("fields = %v, want model binding", model.Occurrence.Fields)
	}

	if call == nil {
		t.Fatal("chat-call did not fire")
	}
	if call.Occurrence.Fields["param.temperature"] != "0.2" {
		t.Errorf("captured params = %v, want param.temperature=0.2", call.Occurrence.Fields)
	}
	if call.Occurrence.Fields["param.max_tokens"] != "512" {
		t.Errorf("captured params = %v, want param.max_tokens=512", call.Occurrence.Fields)
	}
	if len(call.Relations) != 1 || call.Relations[0].Target.FromField != "model" {
		t.Errorf("relations = %+v", call.Relations)
	}

	// The commented model id must NOT produce a finding (comments never scanned).
	for _, f := range findings {
		if strings.Contains(f.Claim.Name, "in-a-comment") {
			t.Error("comment region produced a finding")
		}
	}
}

// TestKeywordPrefilterGates: a file with no keyword hit runs zero regexes
// and yields zero findings.
func TestKeywordPrefilterGates(t *testing.T) {
	m := loadTestPack(t, openaiPack)
	if got := detectOn(t, m, "clean.py", "print('no ai here')\n"); len(got) != 0 {
		t.Errorf("findings = %+v, want none", got)
	}
	// keyword present ONLY in a comment: prefilter runs on masked buffer
	if got := detectOn(t, m, "c.py", "# gpt-4.1 mentioned in comment only\nx = 1\n"); len(got) != 0 {
		t.Errorf("comment-only keyword produced findings: %+v", got)
	}
}

// TestLanguageGate: rules with a language list never fire on other
// languages.
func TestLanguageGate(t *testing.T) {
	m := loadTestPack(t, openaiPack)
	// model-literal is language-gated; .txt classifies as unknown.
	if got := detectOn(t, m, "notes.txt", `model="gpt-4.1"`); len(got) != 0 {
		t.Errorf("unknown-language file produced language-gated findings: %+v", got)
	}
}

// TestSharedKeywordAcrossRules: two rules sharing a keyword string must
// both activate (the trie dedupes needles; owners must not collapse).
func TestSharedKeywordAcrossRules(t *testing.T) {
	pack := `
pack: shared
version: 1
rules:
  - id: shared/rule-a
    kind: hosted-llm
    provider: p
    keywords: ["needle"]
    pattern: 'needle-a-(?P<model>\w+)'
    claim: { name: "${model}" }
    confidence: 0.5
  - id: shared/rule-b
    kind: vector-db
    keywords: ["needle"]
    pattern: 'needle-b-(?P<name>\w+)'
    claim: { name: "${name}" }
    confidence: 0.5
`
	m := loadTestPack(t, pack)
	findings := detectOn(t, m, "x.py", "a = 'needle-a-one'\nb = 'needle-b-two'\n")
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want both rules to fire: %+v", len(findings), findings)
	}
}

// TestValidationTable: the startup lint contract rejects each violation
// with a useful error.
func TestValidationTable(t *testing.T) {
	base := func(mutate string) string {
		return strings.Replace(`
pack: test
version: 1
rules:
  - id: test/rule
    kind: hosted-llm
    keywords: ["kw"]
    pattern: 'kw-(?P<model>\w+)'
    claim: { name: "${model}" }
    confidence: 0.8
`, "PLACEHOLDER", "", 1) + mutate
	}
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"no keywords", strings.Replace(base(""), `keywords: ["kw"]`, "keywords: []", 1), "keywords is mandatory"},
		{"bad regex", strings.Replace(base(""), `pattern: 'kw-(?P<model>\w+)'`, `pattern: 'kw-(unclosed'`, 1), "does not compile"},
		{"bad kind", strings.Replace(base(""), "kind: hosted-llm", "kind: local-model-file", 1), "not rule-expressible"},
		{"confidence 1.0", strings.Replace(base(""), "confidence: 0.8", "confidence: 1.0", 1), "confidence"},
		{"unreferenced group", strings.Replace(base(""), `pattern: 'kw-(?P<model>\w+)'`, `pattern: 'kw-(?P<model>\w+)-(?P<extra>\w+)'`, 1), "never referenced"},
		{"unknown template var", strings.Replace(base(""), `claim: { name: "${model}" }`, `claim: { name: "${nope}" }`, 1), "not a named group"},
		{"bad language", strings.Replace(base(""), `kind: hosted-llm`, "kind: hosted-llm\n    languages: [cobol]", 1), "unsupported language"},
		{"bad region", strings.Replace(base(""), `kind: hosted-llm`, "kind: hosted-llm\n    regions: [comment]", 1), "subset of [code, string]"},
		{"unknown yaml key", strings.Replace(base(""), "confidence: 0.8", "confidence: 0.8\n    surprise: true", 1), "field surprise not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(nil, []string{"test.yaml"}, func(string) ([]byte, error) { return []byte(tc.yaml), nil })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// TestOverlayMergeSemantics: add (namespaced), override (whole rule),
// disable — later layers win (docs/rule-schema.md).
func TestOverlayMergeSemantics(t *testing.T) {
	overlay := `
pack: mycorp
version: 1
rules:
  - id: openai/model-literal
    disable: true
  - id: mycorp/custom
    kind: hosted-llm
    provider: mycorp
    keywords: ["mycorp-llm"]
    pattern: 'mycorp-llm-(?P<model>\w+)'
    claim: { name: "${model}" }
    confidence: 0.9
`
	files := map[string]string{"openai.yaml": openaiPack, "extra.yaml": overlay}
	rs, err := Load(nil, []string{"openai.yaml", "extra.yaml"}, func(p string) ([]byte, error) {
		return []byte(files[p]), nil
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ids := map[string]bool{}
	for _, r := range rs.Rules {
		ids[r.ID] = true
	}
	if ids["openai/model-literal"] {
		t.Error("disabled rule survived")
	}
	if !ids["openai/chat-call"] || !ids["mycorp/custom"] {
		t.Errorf("effective rules wrong: %v", ids)
	}

	// A non-namespaced ADD must be rejected.
	bad := `
pack: mycorp
version: 1
rules:
  - id: other/rule
    kind: hosted-llm
    keywords: ["x"]
    pattern: 'x(?P<model>\w+)'
    claim: { name: "${model}" }
    confidence: 0.5
`
	if _, err := Load(nil, []string{"bad.yaml"}, func(string) ([]byte, error) { return []byte(bad), nil }); err == nil {
		t.Error("non-namespaced overlay add accepted")
	}
}

// TestRulesetHashChangesOnAnyEdit: the self-invalidating cache-key
// ingredient.
func TestRulesetHashChangesOnAnyEdit(t *testing.T) {
	h1 := loadTestPack(t, openaiPack).Hash()
	h2 := loadTestPack(t, strings.Replace(openaiPack, "confidence: 0.85", "confidence: 0.86", 1)).Hash()
	if h1 == h2 {
		t.Error("editing a rule did not change the effective-ruleset hash")
	}
	if h1 != loadTestPack(t, openaiPack).Hash() {
		t.Error("hash is not deterministic")
	}
}

// TestMatchCap: pathological inputs are bounded (P2).
func TestMatchCap(t *testing.T) {
	m := loadTestPack(t, openaiPack)
	var b strings.Builder
	for i := 0; i < maxMatchesPerRulePerFile+50; i++ {
		fmt.Fprintf(&b, "model=\"gpt-4.%d\"\n", i)
	}
	findings := detectOn(t, m, "gen.py", b.String())
	count := 0
	for _, f := range findings {
		if f.Occurrence.DetectorID == "rules/openai/model-literal" {
			count++
		}
	}
	if count != maxMatchesPerRulePerFile {
		t.Errorf("matches = %d, want capped at %d", count, maxMatchesPerRulePerFile)
	}
}

// TestCaptureParamsNearestCallSite is the window-bleed regression: with two
// calls a few lines apart, each call's occurrence must carry ITS OWN model
// and params — a preceding call's bindings must not shadow them (§9.5, D12).
func TestCaptureParamsNearestCallSite(t *testing.T) {
	m := loadTestPack(t, openaiPack)
	src := `import openai
client = openai.OpenAI()

a = client.chat.completions.create(
    model="gpt-4.1",
    temperature=0.1,
)

b = client.chat.completions.create(
    model="o3",
    temperature=0.9,
)
`
	findings := detectOn(t, m, "two.py", src)
	var calls []detect.Finding
	for _, f := range findings {
		if f.Occurrence.DetectorID == "rules/openai/chat-call" {
			calls = append(calls, f)
		}
	}
	if len(calls) != 2 {
		t.Fatalf("chat-call findings = %d, want 2", len(calls))
	}
	// findings are emitted in match order: call A (line 4) then call B (line 9)
	a, b := calls[0], calls[1]
	if a.Occurrence.Fields["model"] != "gpt-4.1" || a.Occurrence.Fields["param.temperature"] != "0.1" {
		t.Errorf("call A fields = %v, want its own model/temperature", a.Occurrence.Fields)
	}
	if b.Occurrence.Fields["model"] != "o3" || b.Occurrence.Fields["param.temperature"] != "0.9" {
		t.Errorf("call B fields = %v, want its own model/temperature (not call A's)", b.Occurrence.Fields)
	}
}

// TestPrefilterFoldsCaseAndWhitespace: a (?i) or \s+ pattern must fire across
// casing and whitespace variants; the Aho–Corasick prefilter is folded so a
// single-cased, single-spaced literal keyword no longer defeats it. (Phase 10
// review, ruleengine findings.)
func TestPrefilterFoldsCaseAndWhitespace(t *testing.T) {
	pack := `pack: fold
version: 1
rules:
  - id: fold/vllm
    kind: infra
    languages: [python]
    keywords: ["vllm serve"]
    pattern: '\bvllm\s+serve\b'
    claim: { name: "vllm" }
    confidence: 0.7
  - id: fold/pgvector
    kind: vector-db
    languages: [python]
    keywords: ["CREATE EXTENSION"]
    pattern: '(?i)create\s+extension\s+vector'
    claim: { name: "pgvector" }
    confidence: 0.7
`
	m := loadTestPack(t, pack)
	cases := []struct {
		name    string
		content string
	}{
		{"vllm single space", `cmd = "vllm serve model"`},
		{"vllm double space", `cmd = "vllm  serve model"`},
		{"vllm tab", "cmd = \"vllm\tserve model\""},
		{"pgvector upper", `q = "CREATE EXTENSION vector"`},
		{"pgvector title", `q = "Create Extension vector"`},
		{"pgvector mixed", `q = "CREATE extension vector"`},
	}
	for _, tc := range cases {
		if got := detectOn(t, m, "a.py", tc.content); len(got) != 1 {
			t.Errorf("%s: got %d findings, want 1", tc.name, len(got))
		}
	}
}
