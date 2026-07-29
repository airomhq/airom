package detect_test

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom/detect"
)

func TestIsAIROMConfig(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"rule pack", "pack: prompts\nversion: 1\nrules:\n  - id: prompts/langchain\n    kind: prompt\n", true},
		{
			"lifecycle catalog",
			"provider: openai\nsource: https://x\nverified: 2026-07-23\nmodels:\n  - {id: gpt-4, state: deprecated}\n",
			true,
		},

		// ── Everything a scanned project might legitimately own ──
		// A real prompt asset. This is the case the guard must not swallow: it
		// is YAML, it lives beside rule packs, and it IS a finding.
		{"a real prompt", "system: |\n  You are a helpful assistant.\nuser: \"{{question}}\"\n", false},
		// `provider:` alone is an ordinary key — Terraform, CI configs, and
		// plenty of app configs carry it. Requiring models+verified alongside is
		// what keeps this from hiding a project's own configuration.
		{"provider key alone", "provider: aws\nregion: us-east-1\n", false},
		{"provider with models but no verified date", "provider: acme\nmodels:\n  - a\n  - b\n", false},
		{"pack key without rules", "pack: something\nname: x\n", false},
		{"rules key without pack", "rules:\n  - allow\n  - deny\n", false},
		{"empty", "", false},
		{"not yaml", "\x00\x01binary", false},
		{"json prompt", `{"system": "You are helpful", "user": "{{q}}"}`, false},
		// The reason only column-0 keys count: a prompt whose BODY happens to
		// contain these words must stay a finding. Indented text belongs to the
		// block scalar above it, not to the document.
		{
			"prompt whose body mentions rules and models",
			"system: |\n  You are a helpful assistant.\n  rules:\n    - be concise\n  models:\n    - gpt-4\n  verified: yes\n  pack: anything\n",
			false,
		},
		{"a YAML list document", "- pack\n- rules\n", false},
	}
	for _, tc := range cases {
		if got := detect.IsAIROMConfig([]byte(tc.body)); got != tc.want {
			t.Errorf("IsAIROMConfig(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
