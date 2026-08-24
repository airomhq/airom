// Package treesitter implements high-precision language AST parsers running inside the WASM sandbox.
package treesitter

import (
	"github.com/airomhq/airom/internal/wasm"
)

// Parser provides AST parsing and model call-site extraction for a specific programming language.
type Parser interface {
	Language() wasm.Language
	Parse(source []byte) (*wasm.ASTNode, []wasm.CallSite, error)
}

// ExtractedBinding represents an identified model or AI framework reference in code.
type ExtractedBinding struct {
	Framework    string            `json:"framework"` // openai | anthropic | langchain | huggingface | vercel-ai
	ModelName    string            `json:"modelName"`
	Task         string            `json:"task,omitempty"`
	Parameters   map[string]string `json:"parameters,omitempty"`
	LineNumber   int               `json:"lineNumber"`
	Confidence   float64           `json:"confidence"`
	IsTestScoped bool              `json:"isTestScoped"`
}
