// Package hybrid implements the two-stage hybrid scan pipeline: Aho-Corasick fast-path
// pre-filtering coupled with sandboxed Tree-Sitter WASM AST evaluation (ARCHITECTURE.md §6, §16).
package hybrid

import (
	"context"

	"github.com/cloudflare/ahocorasick"

	"github.com/airomhq/airom/internal/wasm"
	"github.com/airomhq/airom/internal/wasm/treesitter"
)

// Pipeline combines fast literal prefiltering with AST parsing.
type Pipeline struct {
	engine   *wasm.Engine
	matcher  *ahocorasick.Matcher
	keywords []string
}

// NewPipeline constructs a hybrid AST pipeline with pre-compiled AI candidate keywords.
func NewPipeline(engine *wasm.Engine) *Pipeline {
	if engine == nil {
		engine = wasm.NewEngine(wasm.DefaultSandboxConfig())
	}

	keywords := []string{
		"openai", "anthropic", "chatcompletion", "gpt-", "claude-", "llama", "mistral",
		"gemini", "bedrock", "ollama", "vllm", "langchain", "llamaindex", "transformers",
		"from_pretrained", "pipeline", "torch.load", "safetensors", "qdrant", "chroma",
		"weaviate", "pinecone", "milvus", "fastmcp", "mcp", "model",
	}

	matcher := ahocorasick.NewStringMatcher(keywords)

	return &Pipeline{
		engine:   engine,
		matcher:  matcher,
		keywords: keywords,
	}
}

// ScanFile executes the two-stage hybrid analysis on a source file.
func (p *Pipeline) ScanFile(ctx context.Context, lang wasm.Language, source []byte) (hasCandidates bool, calls []wasm.CallSite, err error) {
	// Stage 1: Aho-Corasick fast-path prefilter (thread-safe)
	matches := p.matcher.MatchThreadSafe(source)
	if len(matches) == 0 {
		// Fast-path: zero candidate keywords, skip expensive AST parsing
		return false, nil, nil
	}

	// Stage 2: Candidate keywords detected -> dispatch to sandboxed Tree-Sitter AST parser
	parser := treesitter.SystemsParserFactory(lang)

	_, extractedCalls, _, parseErr := p.engine.Execute(ctx, lang, source, func(c context.Context, code []byte) (*wasm.ASTNode, []wasm.CallSite, error) {
		return parser.Parse(code)
	})

	if parseErr != nil {
		return true, nil, parseErr
	}

	return true, extractedCalls, nil
}

// Close closes the underlying WASM engine.
func (p *Pipeline) Close() error {
	if p.engine != nil {
		return p.engine.Close()
	}
	return nil
}
