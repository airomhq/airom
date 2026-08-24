package treesitter

import (
	"regexp"
	"strings"

	"github.com/airomhq/airom/internal/wasm"
)

// PythonParser parses Python source files to extract AI model call sites and kwargs.
type PythonParser struct{}

// NewPythonParser constructs a Python AST parser.
func NewPythonParser() *PythonParser {
	return &PythonParser{}
}

// Language returns wasm.LangPython.
func (p *PythonParser) Language() wasm.Language {
	return wasm.LangPython
}

var (
	pyFromPretrained = regexp.MustCompile(`(?i)\.from_pretrained\s*\(\s*["']([^"']+)["']`)
	pyHFPipeline     = regexp.MustCompile(`(?i)pipeline\s*\(\s*["']([^"']+)["'](?:\s*,\s*model\s*=\s*["']([^"']+)["'])?`)
	pyMultiCallRegex = regexp.MustCompile(`(?is)(?:([a-zA-Z0-9_\.]+)\.)?([a-zA-Z0-9_]+)\s*\(([^)]*)\)`)
	pyKwargRegex     = regexp.MustCompile(`([a-zA-Z0-9_]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([0-9\.]+|True|False|None))`)
)

// Parse extracts call sites from Python source code.
func (p *PythonParser) Parse(source []byte) (*wasm.ASTNode, []wasm.CallSite, error) {
	srcStr := string(source)
	lines := strings.Split(srcStr, "\n")
	var callSites []wasm.CallSite

	rootNode := &wasm.ASTNode{
		Type:      "module",
		StartLine: 1,
		EndLine:   len(lines),
	}

	// 1. Check HuggingFace patterns across lines
	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		if match := pyFromPretrained.FindStringSubmatch(line); len(match) > 1 {
			callSites = append(callSites, wasm.CallSite{
				Function: "from_pretrained",
				Receiver: "transformers",
				Kwargs: map[string]string{
					"model": match[1],
				},
				LineNumber: lineNum,
			})
		}
		if match := pyHFPipeline.FindStringSubmatch(line); len(match) > 1 {
			task := match[1]
			model := ""
			if len(match) > 2 {
				model = match[2]
			}
			callSites = append(callSites, wasm.CallSite{
				Function: "pipeline",
				Receiver: "transformers",
				Kwargs: map[string]string{
					"task":  task,
					"model": model,
				},
				LineNumber: lineNum,
			})
		}
	}

	// 2. Multiline call extraction
	callMatches := pyMultiCallRegex.FindAllStringSubmatchIndex(srcStr, -1)
	for _, idxs := range callMatches {
		fullMatch := srcStr[idxs[0]:idxs[1]]
		receiver := ""
		if idxs[2] != -1 && idxs[3] != -1 {
			receiver = srcStr[idxs[2]:idxs[3]]
		}
		fn := srcStr[idxs[4]:idxs[5]]
		argsContent := ""
		if idxs[6] != -1 && idxs[7] != -1 {
			argsContent = srcStr[idxs[6]:idxs[7]]
		}

		kwargs := make(map[string]string)
		kwMatches := pyKwargRegex.FindAllStringSubmatch(argsContent, -1)
		for _, kw := range kwMatches {
			k := kw[1]
			v := kw[2]
			if v == "" {
				v = kw[3]
			}
			if v == "" {
				v = kw[4]
			}
			kwargs[k] = v
		}

		if isRelevantAIFunction(fn, receiver, kwargs) {
			lineNum := strings.Count(srcStr[:idxs[0]], "\n") + 1
			callSites = append(callSites, wasm.CallSite{
				Function:   fn,
				Receiver:   receiver,
				Kwargs:     kwargs,
				LineNumber: lineNum,
			})
		}
		_ = fullMatch
	}

	return rootNode, callSites, nil
}

func isRelevantAIFunction(fn, receiver string, kwargs map[string]string) bool {
	if _, ok := kwargs["model"]; ok {
		return true
	}
	if _, ok := kwargs["temperature"]; ok {
		return true
	}
	fnLower := strings.ToLower(fn)
	if strings.Contains(fnLower, "chatopenai") || strings.Contains(fnLower, "anthropic") ||
		strings.Contains(fnLower, "gemini") || strings.Contains(fnLower, "bedrock") ||
		strings.Contains(fnLower, "ollama") || strings.Contains(fnLower, "vllm") {
		return true
	}
	return false
}
