package prompt

import (
	"context"
	"testing"

	"github.com/airomhq/airom/pkg/airom/detect"
	"github.com/airomhq/airom/pkg/airom/detectortest"
)

func TestPrompt(t *testing.T) {
	detectortest.Run(t, NewPrompt(), detectortest.Fixtures{Dir: "testdata"})
}

// TestSourceCodeUnderPromptsIsNotAPrompt: the `**/prompts/**` glob routes an
// entire directory, and the `prompts`/`enquirer` npm package files its source
// there. Code is never a prompt asset — in-code prompt usage is the rule packs'
// job (§6.3).
func TestSourceCodeUnderPromptsIsNotAPrompt(t *testing.T) {
	for _, p := range []string{
		"node_modules/enquirer/lib/prompts/autocomplete.js",
		"lib/prompts/confirm.js",
		"src/prompts/input.ts",
		"app/prompts/render.py",
		"internal/prompts/loader.go",
	} {
		f := file(t, p, "const Select = require('./select');\nmodule.exports = AutoComplete;\n")
		got, err := NewPrompt().DetectFile(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("%s: reported as a prompt; source code is never a prompt asset", p)
		}
	}
}

// TestCodegenTemplateIsNotAPrompt: jinja syntax alone means a template engine,
// not an LLM. A codegen template that merely mentions "system" is not a prompt.
func TestCodegenTemplateIsNotAPrompt(t *testing.T) {
	body := "{% for metric in metrics %}\nconst {{ metric.name }} = \"{{ metric.id }}\"  // subsystem: {{ metric.system }}\n{% endfor %}\n"
	for _, p := range []string{"templates/metric.go.j2", "codegen/attribute_group.go.j2", "tpl/helpers.j2"} {
		f := file(t, p, body)
		got, err := NewPrompt().DetectFile(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("%s: reported as a prompt; jinja syntax is a template engine, not an LLM", p)
		}
	}
}

// TestRealPromptTemplatesStillDetected: the gate must not silence real prompts,
// including one filed outside a prompts/ directory.
func TestRealPromptTemplatesStillDetected(t *testing.T) {
	cases := []struct {
		path, body string
		wantConf   float64
	}{
		{"templates/agent.jinja", "{% if role == \"system\" %}\nYou are {{ agent_name }}, an agent.\n{% endif %}\n", 0.8},
		{"prompts/system.txt", "You are a helpful research assistant.\n", 0.8},
		{"summarize.prompt", "Summarize the following document:\n", 0.6},
		{"chat.j2", "{{ messages }}\nassistant: {{ reply }}\n", 0.8},
	}
	for _, c := range cases {
		got, err := NewPrompt().DetectFile(context.Background(), file(t, c.path, c.body))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Errorf("%s: got %d findings, want 1 (a real prompt)", c.path, len(got))
			continue
		}
		if float64(got[0].Occurrence.Confidence) != c.wantConf {
			t.Errorf("%s: confidence %.2f, want %.2f", c.path, got[0].Occurrence.Confidence, c.wantConf)
		}
	}
}

// file builds a detect.File for path with the given content.
func file(t *testing.T, p, content string) *detect.File {
	t.Helper()
	b := []byte(content)
	return detect.NewFile(
		detect.FileRef{Path: p, Size: int64(len(b))},
		b,
		detect.FileProviders{Content: func() ([]byte, bool, error) { return b, false, nil }},
	)
}

// TestAIROMConfigIsNotAPrompt: a rule pack is YAML full of provider names and
// prompt patterns, so a project that keeps its custom packs under prompts/ had
// its detection CONFIGURATION inventoried as part of the software being
// scanned. AIROM's own rules/prompts/prompts.yaml was the first casualty; a
// user's mycorp-prompts.yaml is the one that matters.
func TestAIROMConfigIsNotAPrompt(t *testing.T) {
	cases := map[string]string{
		"prompts/mycorp.yaml":   "pack: mycorp\nversion: 1\nrules:\n  - id: mycorp/template\n    kind: prompt\n",
		"prompts/lifecycle.yml": "provider: openai\nsource: https://x\nverified: 2026-07-23\nmodels:\n  - {id: gpt-4, state: deprecated}\n",
	}
	for p, body := range cases {
		f := file(t, p, body)
		got, err := NewPrompt().DetectFile(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("%s: AIROM's own configuration reported as a prompt asset", p)
		}
	}

	// And the guard must be narrow: a genuine prompt in the same directory,
	// with the same extension, is still a finding.
	f := file(t, "prompts/greeting.yaml", "system: |\n  You are a helpful assistant.\nuser: \"{{question}}\"\n")
	got, err := NewPrompt().DetectFile(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Error("a real prompt beside a rule pack must still be detected")
	}
}
