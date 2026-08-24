package treesitter

import (
	"regexp"
	"strings"

	"github.com/airomhq/airom/internal/wasm"
)

// GoParser extracts AI model call sites and struct literals from Go source code.
type GoParser struct{}

// NewGoParser constructs a Go AST parser.
func NewGoParser() *GoParser { return &GoParser{} }

// Language returns wasm.LangGo.
func (p *GoParser) Language() wasm.Language { return wasm.LangGo }

var (
	goModelLitRegex = regexp.MustCompile(`(?i)Model:\s*["']([^"']+)["']`)
	goClientRegex   = regexp.MustCompile(`(?i)(?:openai|langchaingo|anthropic)\.NewClient\s*\(`)
)

// Parse extracts call sites from Go code.
func (p *GoParser) Parse(source []byte) (*wasm.ASTNode, []wasm.CallSite, error) {
	srcStr := string(source)
	lines := strings.Split(srcStr, "\n")
	var callSites []wasm.CallSite

	rootNode := &wasm.ASTNode{Type: "source_file", StartLine: 1, EndLine: len(lines)}

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		if match := goModelLitRegex.FindStringSubmatch(line); len(match) > 1 {
			callSites = append(callSites, wasm.CallSite{
				Function: "ChatCompletionRequest",
				Receiver: "openai",
				Kwargs: map[string]string{
					"model": match[1],
				},
				LineNumber: lineNum,
			})
		}
	}

	return rootNode, callSites, nil
}

// RustParser extracts AI model call sites and Candle/Tch model loaders from Rust code.
type RustParser struct{}

// NewRustParser constructs a Rust AST parser.
func NewRustParser() *RustParser { return &RustParser{} }

// Language returns wasm.LangRust.
func (p *RustParser) Language() wasm.Language { return wasm.LangRust }

var (
	rustModelCallRegex = regexp.MustCompile(`(?i)\.model\s*\(\s*["']([^"']+)["']\s*\)`)
	rustCandleRegex    = regexp.MustCompile(`(?i)candle_core::Tensor|candle_transformers::models::([a-zA-Z0-9_]+)`)
)

// Parse extracts call sites from Rust code.
func (p *RustParser) Parse(source []byte) (*wasm.ASTNode, []wasm.CallSite, error) {
	srcStr := string(source)
	lines := strings.Split(srcStr, "\n")
	var callSites []wasm.CallSite

	rootNode := &wasm.ASTNode{Type: "source_file", StartLine: 1, EndLine: len(lines)}

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		if match := rustModelCallRegex.FindStringSubmatch(line); len(match) > 1 {
			callSites = append(callSites, wasm.CallSite{
				Function: "model_builder",
				Receiver: "async_openai",
				Kwargs: map[string]string{
					"model": match[1],
				},
				LineNumber: lineNum,
			})
		}
	}

	return rootNode, callSites, nil
}

// JavaParser extracts LangChain4j, Spring AI, and OpenAI Java SDK call sites.
type JavaParser struct{}

// NewJavaParser constructs a Java AST parser.
func NewJavaParser() *JavaParser { return &JavaParser{} }

// Language returns wasm.LangJava.
func (p *JavaParser) Language() wasm.Language { return wasm.LangJava }

var (
	javaModelNameRegex = regexp.MustCompile(`(?i)\.modelName\s*\(\s*["']([^"']+)["']\s*\)`)
	javaOpenAIRegex    = regexp.MustCompile(`(?i)OpenAiChatModel\.builder\(\)`)
)

// Parse extracts call sites from Java code.
func (p *JavaParser) Parse(source []byte) (*wasm.ASTNode, []wasm.CallSite, error) {
	srcStr := string(source)
	lines := strings.Split(srcStr, "\n")
	var callSites []wasm.CallSite

	rootNode := &wasm.ASTNode{Type: "compilation_unit", StartLine: 1, EndLine: len(lines)}

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		if match := javaModelNameRegex.FindStringSubmatch(line); len(match) > 1 {
			callSites = append(callSites, wasm.CallSite{
				Function: "modelName",
				Receiver: "dev.langchain4j",
				Kwargs: map[string]string{
					"model": match[1],
				},
				LineNumber: lineNum,
			})
		}
	}

	return rootNode, callSites, nil
}

// SystemsParserFactory returns the appropriate parser for a given language.
func SystemsParserFactory(lang wasm.Language) Parser {
	switch lang {
	case wasm.LangGo:
		return NewGoParser()
	case wasm.LangRust:
		return NewRustParser()
	case wasm.LangJava:
		return NewJavaParser()
	case wasm.LangPython:
		return NewPythonParser()
	case wasm.LangTypeScript, wasm.LangJavaScript:
		return NewTypeScriptParser()
	default:
		return NewPythonParser()
	}
}
