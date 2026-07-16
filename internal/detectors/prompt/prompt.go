package prompt

import (
	"bytes"
	"context"
	"strings"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// maxPromptSize bounds the files this detector will consider — a prompt is
// text, not a corpus.
const maxPromptSize = 1 << 20 // 1 MiB

// Prompt detects prompt assets stored as standalone files. The selector
// carries the path signal; content markers upgrade confidence and format.
type Prompt struct{}

// NewPrompt constructs the prompt-file detector.
func NewPrompt() *Prompt { return &Prompt{} }

// ID is the stable SARIF ruleId.
func (*Prompt) ID() string { return "prompt/file" }

// Version participates in the cache key; bump on any behavior change.
func (*Prompt) Version() int { return 1 }

// Selector routes prompt-shaped paths: anything under a prompts/ directory or
// carrying a prompt/template extension.
func (*Prompt) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".prompt"},
		PathGlobs: []string{
			"**/prompts/**",
			"**/*.prompt",
			"**/*.prompt.txt",
			"**/*.jinja",
			"**/*.jinja2",
			"**/*.j2",
		},
		MaxSize: maxPromptSize,
		Need:    detect.NeedContent,
	}
}

// systemMarkers are strong, prompt-defining phrases (matched lowercased).
var systemMarkers = []string{
	"you are a",
	"your task is",
	"###instruction",
	"### instruction",
}

// roleWords corroborate a jinja template as a chat prompt (matched lowercased).
var roleWords = []string{"system", "assistant", "role"}

// DetectFile judges whether the routed file is a prompt and, if so, emits a
// single whole-file KindPrompt claim.
func (p *Prompt) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	// A NUL byte means this is not the text asset the path implied.
	if bytes.IndexByte(content, 0) >= 0 {
		return nil, nil
	}

	lower := strings.ToLower(string(content))
	jinja := hasJinja(content)
	strong := containsAny(lower, systemMarkers) || (jinja && containsAny(lower, roleWords))

	format := "prompt"
	if jinja {
		format = "prompt-template"
	}

	conf := airom.Confidence(0.6)
	method := airom.MethodFilename
	if strong {
		conf = 0.8
		method = airom.MethodConfig // content-confirmed
	}

	return []detect.Finding{{
		Claim: detect.ComponentClaim{
			Kind: airom.KindPrompt,
			Name: f.Base(),
			Data: &detect.DataClaim{Format: format},
		},
		Occurrence: airom.Occurrence{
			Method:     method,
			Confidence: conf,
		},
	}}, nil
}

// hasJinja reports whether the bytes carry jinja placeholder or block syntax.
func hasJinja(b []byte) bool {
	return bytes.Contains(b, []byte("{{")) || bytes.Contains(b, []byte("{%"))
}

// containsAny reports whether the (already lowercased) text holds any needle.
func containsAny(lower string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}
