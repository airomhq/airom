package treesitter

import (
	"regexp"
	"strings"

	"github.com/airomhq/airom/internal/wasm"
)

// TypeScriptParser parses TypeScript and JavaScript source files to extract AI model call sites.
type TypeScriptParser struct{}

// NewTypeScriptParser constructs a TypeScript AST parser.
func NewTypeScriptParser() *TypeScriptParser {
	return &TypeScriptParser{}
}

// Language returns wasm.LangTypeScript.
func (p *TypeScriptParser) Language() wasm.Language {
	return wasm.LangTypeScript
}

var (
	tsMultiCallRegex = regexp.MustCompile(`(?is)(?:([a-zA-Z0-9_\.]+)\.)?([a-zA-Z0-9_]+)\s*\(\s*\{([^}]*)\}\s*\)`)
	tsPropRegex      = regexp.MustCompile(`([a-zA-Z0-9_]+)\s*:\s*(?:"([^"]*)"|'([^']*)'|` + "`([^`]*)`" + `|([0-9\.]+|true|false))`)
	tsVercelAIRegex  = regexp.MustCompile(`(?i)(?:openai|anthropic|google|cohere)\s*\(\s*["']([^"']+)["']`)
)

// Parse extracts call sites from TypeScript/JavaScript source code.
func (p *TypeScriptParser) Parse(source []byte) (*wasm.ASTNode, []wasm.CallSite, error) {
	srcStr := string(source)
	lines := strings.Split(srcStr, "\n")
	var callSites []wasm.CallSite

	rootNode := &wasm.ASTNode{
		Type:      "program",
		StartLine: 1,
		EndLine:   len(lines),
	}

	// 1. Check Vercel AI SDK per line
	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		if match := tsVercelAIRegex.FindStringSubmatch(line); len(match) > 1 {
			callSites = append(callSites, wasm.CallSite{
				Function: "model_provider_constructor",
				Receiver: "ai",
				Kwargs: map[string]string{
					"model": match[1],
				},
				LineNumber: lineNum,
			})
		}
	}

	// 2. Multiline object call extraction
	callMatches := tsMultiCallRegex.FindAllStringSubmatchIndex(srcStr, -1)
	for _, idxs := range callMatches {
		receiver := ""
		if idxs[2] != -1 && idxs[3] != -1 {
			receiver = srcStr[idxs[2]:idxs[3]]
		}
		fn := srcStr[idxs[4]:idxs[5]]
		propsContent := ""
		if idxs[6] != -1 && idxs[7] != -1 {
			propsContent = srcStr[idxs[6]:idxs[7]]
		}

		kwargs := make(map[string]string)
		propMatches := tsPropRegex.FindAllStringSubmatch(propsContent, -1)
		for _, pm := range propMatches {
			k := pm[1]
			v := pm[2]
			if v == "" {
				v = pm[3]
			}
			if v == "" {
				v = pm[4]
			}
			if v == "" {
				v = pm[5]
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
	}

	return rootNode, callSites, nil
}
