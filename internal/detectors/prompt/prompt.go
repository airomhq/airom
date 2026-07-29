package prompt

import (
	"bytes"
	"context"
	"path"
	"regexp"
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

// chatMarkers are chat-template machinery with no meaning outside an LLM: the
// HuggingFace chat_template vocabulary and the common special tokens.
var chatMarkers = []string{
	"add_generation_prompt", "bos_token", "eos_token",
	"<|im_start|>", "<|im_end|>", "<|system|>", "<|user|>", "<|assistant|>",
	"[inst]", "<<sys>>",
}

// chatRoleTest matches a role BOUND or COMPARED to a chat role literal:
// `role == "system"`, `"role": "user"`, `- role: assistant`. That pairing is the
// chat-completion shape itself.
var chatRoleTest = regexp.MustCompile(`\brole\b["']?\s*(?:==|!=|=|:|\bin\b)\s*[\[("']*\s*(?:system|user|assistant)\b`)

// chatShaped reports whether a template carries chat-completion structure.
//
// This must test the SHAPE, not a bag of words. Asking only whether the words
// "role" and "system" both appear somewhere reports every RBAC, permissions and
// Kubernetes-manifest generator on earth as a prompt — and substring matching
// makes it worse still, since "systemd" contains "system" and "roles" contains
// "role". What actually distinguishes a chat template is a role bound to a chat
// role literal, a loop over `messages`, or the special tokens above; a codegen
// template mentions the same words as unrelated identifiers and forms none of
// those.
func chatShaped(lower string) bool {
	if containsAny(lower, chatMarkers) || chatRoleTest.MatchString(lower) {
		return true
	}
	// "assistant" names a chat role and little else.
	if hasWord(lower, "assistant") {
		return true
	}
	// The transformers chat_template shape: `{% for message in messages %}
	// {{ message['role'] }}`. Note `messages` is a strong dataset field in this
	// codebase's own vocabulary (dataset/signals.go) for the same reason.
	return hasWord(lower, "messages") && hasWord(lower, "role")
}

// hasWord reports whether the (already lowercased) text holds tok as a whole
// word. Substring matching is not good enough here: "subsystem" and "systemd"
// must not answer a test for "system", nor "roles" one for "role".
func hasWord(lower, tok string) bool {
	for i := 0; i+len(tok) <= len(lower); {
		j := strings.Index(lower[i:], tok)
		if j < 0 {
			return false
		}
		j += i
		if wordEdge(lower, j-1) && wordEdge(lower, j+len(tok)) {
			return true
		}
		i = j + 1
	}
	return false
}

// wordEdge reports whether index i falls outside the text or on a byte that
// cannot continue an identifier.
func wordEdge(lower string, i int) bool {
	if i < 0 || i >= len(lower) {
		return true
	}
	return !identByte(lower[i])
}

// identByte reports whether c can continue an identifier. The text is already
// lowercased, so the letter range is a-z only.
func identByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
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
// `.json`/`.toml` belong here for the same reason `.yaml` does: a prompt stored
// as data is data, not code, and prompts/greeting.json is no more a program than
// the prompts/greeting.yaml beside it.
var promptExts = map[string]bool{
	"": true, ".prompt": true, ".txt": true, ".md": true,
	".jinja": true, ".jinja2": true, ".j2": true,
	".yaml": true, ".yml": true, ".json": true, ".toml": true, ".tmpl": true,
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
	// Nor is one of AIROM's own configuration files. A rule pack is YAML full of
	// prompt patterns, so a project keeping its custom packs in prompts/ had its
	// detection config inventoried as the prompts of the software being scanned.
	if detect.IsAIROMConfig(content) {
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
