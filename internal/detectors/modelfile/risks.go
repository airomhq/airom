package modelfile

import (
	"sort"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

// chatTemplateGadgets are constructs that a legitimate GGUF
// tokenizer.chat_template never needs, but that a sandbox-escape / SSTI payload
// relies on to reach the Python runtime. Every real escape routes through a
// dunder attribute traversal (__globals__/__class__/__subclasses__/…) or a
// direct os/subprocess call, so those are the signal. The Jinja pivot OBJECTS
// (namespace, cycler, lipsum) are deliberately NOT here: `namespace(...)` is
// standard loop-state syntax in real Llama/Mistral templates, and the
// dangerous use of any pivot still trips a dunder token. Real templates only
// iterate messages and format strings (`{% for message in messages %}`,
// `{{ bos_token }}`, `.strip()`), so this denylist is high-precision.
var chatTemplateGadgets = []string{
	"__globals__", "__subclasses__", "__bases__", "__mro__",
	"__builtins__", "__import__", "__class__", "__reduce__",
	"os.popen", "os.system", "subprocess",
}

// chatTemplateRisk returns the risk claim for a chat template carrying
// sandbox-escape gadgets, or nil. Detail lists the matched gadget tokens,
// sorted and deduped.
func chatTemplateRisk(template string) []detect.RiskClaim {
	if template == "" {
		return nil
	}
	seen := map[string]bool{}
	var detail []string
	for _, g := range chatTemplateGadgets {
		if strings.Contains(template, g) && !seen[g] {
			seen[g] = true
			detail = append(detail, g)
		}
	}
	if len(detail) == 0 {
		return nil
	}
	sort.Strings(detail)
	return []detect.RiskClaim{{ID: airom.RiskGGUFTemplate, Detail: detail}}
}
