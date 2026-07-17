package prompt

import (
	"bytes"
	"context"
	"path"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
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

// chatShaped reports whether a template carries chat-completion structure.
//
// Requiring the SHAPE, not a single word, is what separates an LLM prompt from a
// code generator's template. `{% if role == "system" %}` is a chat prompt; an
// OpenTelemetry codegen template (metric.go.j2) may well contain the word
// "system" on its own, and matching that alone reported it as a prompt.
func chatShaped(lower string) bool {
	if strings.Contains(lower, "assistant") {
		return true
	}
	return strings.Contains(lower, "role") && strings.Contains(lower, "system")
}

// promptExts are the extensions a standalone prompt ASSET can carry.
//
// The `**/prompts/**` glob routes everything under such a directory, which drags
// in source code: the `prompts`/`enquirer` npm package ships autocomplete.js,
// confirm.js and input.js under exactly that path, and each was reported as a
// prompt. But in-code prompt usage is the rule packs' job (§6.3) — this detector
// exists only to judge whether a whole TEXT file is a prompt. So code is refused
// here regardless of where it sits. The empty string admits extensionless files
// (a bare `system-prompt`).
var promptExts = map[string]bool{
	"": true, ".prompt": true, ".txt": true, ".md": true,
	".jinja": true, ".jinja2": true, ".j2": true,
	".yaml": true, ".yml": true, ".tmpl": true,
}

// namedAsPrompt reports whether the PATH claims the file is a prompt: a
// .prompt extension, a *.prompt.* name, or residence in a prompts/ directory.
func namedAsPrompt(p string) bool {
	lower := strings.ToLower(p)
	ext := path.Ext(lower)
	if ext == ".prompt" {
		return true
	}
	base := path.Base(lower)
	if strings.Contains(base, ".prompt.") || strings.Contains(base, "prompt") {
		return true
	}
	for _, seg := range strings.Split(path.Dir(lower), "/") {
		if seg == "prompt" || seg == "prompts" {
			return true
		}
	}
	return false
}

// DetectFile judges whether the routed file is a prompt and, if so, emits a
// single whole-file KindPrompt claim.
//
// Being routed is not enough. A bare .j2/.jinja is a template engine's file, not
// an LLM prompt — codegen templates (attribute_group.go.j2, metric.go.j2) were
// being reported as prompts purely for having jinja syntax. So the file must
// either say what it is (a prompt-defining phrase) or be filed as one; a
// template that merely mentions "system" while sitting outside a prompts/
// directory is neither.
func (p *Prompt) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	if !promptExts[strings.ToLower(path.Ext(f.Path()))] {
		return nil, nil // source code, whatever directory it lives in
	}

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
	named := namedAsPrompt(f.Path())

	// Content evidence: the file says it is a prompt, either in prose or by
	// carrying chat-completion structure. Either stands on its own, wherever
	// the file lives — a prompt template under templates/ is still a prompt.
	confirmed := containsAny(lower, systemMarkers) || (jinja && chatShaped(lower))

	var (
		conf   airom.Confidence
		method airom.DetectionMethod
	)
	switch {
	case confirmed:
		conf, method = 0.8, airom.MethodConfig // content-confirmed
	case named:
		conf, method = 0.6, airom.MethodFilename
	default:
		return nil, nil // a template, or a text file, but not a prompt
	}

	format := "prompt"
	if jinja {
		format = "prompt-template"
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
