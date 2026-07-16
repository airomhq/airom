package infra

import (
	"sort"
	"strings"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// imageSignatures maps a base-image substring to the serving tool it names.
// Checked in order; the first substring the reference contains wins.
var imageSignatures = []struct {
	substr string
	tool   string
}{
	{"ollama/ollama", "ollama"},
	{"vllm/vllm-openai", "vllm"},
	{"vllm/vllm", "vllm"},
	{"huggingface/text-generation-inference", "tgi"},
	{"nvidia/tritonserver", "triton"},
	{"rayproject/ray", "ray"},
}

// aiEnvKeys are environment variables that signal AI serving infrastructure.
var aiEnvKeys = []string{"OLLAMA_HOST", "MODEL_ID", "HUGGING_FACE_HUB_TOKEN"}

// matchImage returns the serving tool named by a base-image reference.
func matchImage(ref string) (string, bool) {
	for _, sig := range imageSignatures {
		if strings.Contains(ref, sig.substr) {
			return sig.tool, true
		}
	}
	return "", false
}

// hit is one recognized serving tool with the endpoint and env keys scoped
// to it (attributed by proximity during the line scan).
type hit struct {
	tool     string
	line     int
	conf     airom.Confidence
	endpoint string
	envKeys  map[string]bool
}

// newHit starts a hit for a tool at a 1-based line.
func newHit(tool string, line int, conf airom.Confidence) *hit {
	return &hit{tool: tool, line: line, conf: conf, envKeys: map[string]bool{}}
}

// addEnv records every AI env key mentioned on a line.
func (h *hit) addEnv(line string) {
	for _, k := range aiEnvKeys {
		if strings.Contains(line, k) {
			h.envKeys[k] = true
		}
	}
}

// finding renders the hit as a detector finding.
func (h *hit) finding() detect.Finding {
	claim := detect.ComponentClaim{Kind: airom.KindInfra, Name: h.tool}
	if h.endpoint != "" {
		claim.Infra = &detect.InfraClaim{Endpoint: h.endpoint}
	}
	var fields map[string]string
	if len(h.envKeys) > 0 {
		keys := make([]string, 0, len(h.envKeys))
		for k := range h.envKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fields = map[string]string{"env": strings.Join(keys, ",")}
	}
	return detect.Finding{
		Claim: claim,
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Line: h.line},
			Method:     airom.MethodConfig,
			Confidence: h.conf,
			Fields:     fields,
		},
	}
}

// findings renders a list of hits in scan order.
func findings(hits []*hit) []detect.Finding {
	if len(hits) == 0 {
		return nil
	}
	out := make([]detect.Finding, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.finding())
	}
	return out
}

// firstPort extracts the leading port number from a whitespace-separated
// EXPOSE argument list (e.g. "8000/tcp 9000" → "8000").
func firstPort(arg string) string {
	for _, tok := range strings.Fields(arg) {
		if p := digitsBefore(tok, '/'); p != "" {
			return p
		}
	}
	return ""
}

// digitsBefore returns tok up to sep if that prefix is all digits.
func digitsBefore(tok string, sep byte) string {
	if i := strings.IndexByte(tok, sep); i >= 0 {
		tok = tok[:i]
	}
	if !allDigits(tok) {
		return ""
	}
	return tok
}

// allDigits reports whether s is a non-empty run of ASCII digits.
func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}
