package gosrc

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// GoSource is the Go AST detector: it reads import specs and obvious
// model-name literals to attribute AI SDK usage precisely (MethodAST).
type GoSource struct{}

// NewGoSource constructs the Go source detector.
func NewGoSource() *GoSource { return &GoSource{} }

// ID is the stable SARIF ruleId.
func (*GoSource) ID() string { return "gosrc/ast" }

// Version participates in the cache key; bump on any behavior change.
func (*GoSource) Version() int { return 1 }

// Selector routes every .go file (by extension and language) to DetectFile.
func (*GoSource) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".go"},
		Languages:  []detect.Language{detect.LangGo},
		Need:       detect.NeedContent,
	}
}

// aiModule is a known AI import prefix and the component kind it implies.
type aiModule struct {
	prefix string
	kind   airom.ComponentKind
}

// aiModules is the recognized set of Go AI SDK import prefixes. A prefix
// matches an import path that equals it or is a subpackage of it.
var aiModules = []aiModule{
	{"github.com/sashabaranov/go-openai", airom.KindLibrary},
	{"github.com/tmc/langchaingo", airom.KindFramework},
	{"github.com/pinecone-io/go-pinecone", airom.KindVectorDB},
	{"github.com/qdrant/go-client", airom.KindVectorDB},
	{"github.com/ollama/ollama/api", airom.KindLibrary},
	{"github.com/milvus-io", airom.KindVectorDB},
}

// DetectFile parses the file and emits import and model-literal findings. A
// syntactically broken file is not our failure: it yields (nil, nil).
func (d *GoSource) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	src, err := f.Content()
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	file, perr := parser.ParseFile(fset, f.Path(), src, parser.SkipObjectResolution)
	if perr != nil {
		return nil, nil //nolint:nilerr // a syntax-broken file is not a detector failure (D1)
	}

	var findings []detect.Finding
	hasAI := false
	for _, imp := range file.Imports {
		p, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			continue
		}
		mod, ok := matchModule(p)
		if !ok {
			continue
		}
		hasAI = true
		findings = append(findings, importFinding(mod, p, fset.Position(imp.Pos()).Line))
	}

	// Model-name string literals are only trusted inside files that already
	// import a known client — that is the "in a call to those clients" guard.
	if hasAI {
		findings = append(findings, modelLiterals(fset, file)...)
	}
	return findings, nil
}

// matchModule returns the AI module whose prefix covers the import path.
func matchModule(p string) (aiModule, bool) {
	for _, m := range aiModules {
		if p == m.prefix || strings.HasPrefix(p, m.prefix+"/") {
			return m, true
		}
	}
	return aiModule{}, false
}

// moduleRoot reduces a VCS import path to its module root (host/org/repo).
func moduleRoot(p string) string {
	segs := strings.Split(p, "/")
	if len(segs) >= 3 {
		switch segs[0] {
		case "github.com", "gitlab.com", "bitbucket.org":
			return strings.Join(segs[:3], "/")
		}
	}
	return p
}

// importFinding builds the library/framework/vector-db claim for an import.
func importFinding(mod aiModule, importPath string, line int) detect.Finding {
	return detect.Finding{
		Claim: detect.ComponentClaim{
			Kind:    mod.kind,
			Name:    moduleRoot(importPath),
			Package: &detect.PackageClaim{Ecosystem: "golang"},
		},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Line: line},
			Method:     airom.MethodAST,
			Confidence: 0.8,
		},
	}
}

// modelLiterals walks each declaration for string literals bound to a
// model-shaped identifier, emitting a hosted-llm claim per literal.
func modelLiterals(fset *token.FileSet, file *ast.File) []detect.Finding {
	var out []detect.Finding
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Body == nil {
				continue
			}
			collectModelLiterals(fset, d.Body, d.Name.Name, &out)
		case *ast.GenDecl:
			collectModelLiterals(fset, d, "", &out)
		}
	}
	return out
}

// collectModelLiterals inspects a subtree for the three shapes a model
// literal can take: a struct field key/value, an assignment, or a var/const
// spec.
func collectModelLiterals(fset *token.FileSet, root ast.Node, symbol string, out *[]detect.Finding) {
	emit := func(name string, pos token.Pos) {
		*out = append(*out, modelFinding(name, fset.Position(pos).Line, symbol))
	}
	ast.Inspect(root, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok && isModelName(key.Name) {
				if v, ok := stringLit(node.Value); ok {
					emit(v, node.Value.Pos())
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if i >= len(node.Rhs) || !isModelName(assignTargetName(lhs)) {
					continue
				}
				if v, ok := stringLit(node.Rhs[i]); ok {
					emit(v, node.Rhs[i].Pos())
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if i >= len(node.Values) || !isModelName(name.Name) {
					continue
				}
				if v, ok := stringLit(node.Values[i]); ok {
					emit(v, node.Values[i].Pos())
				}
			}
		}
		return true
	})
}

// modelFinding builds a hosted-llm claim for a model-name literal.
func modelFinding(name string, line int, symbol string) detect.Finding {
	return detect.Finding{
		Claim: detect.ComponentClaim{Kind: airom.KindHostedLLM, Name: name},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Line: line},
			Method:     airom.MethodAST,
			Confidence: 0.75,
			Symbol:     symbol,
		},
	}
}

// assignTargetName returns the identifier a bare or field assignment targets.
func assignTargetName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// isModelName reports whether an identifier names a model field or variable.
func isModelName(name string) bool {
	switch strings.ToLower(name) {
	case "model", "modelname", "modelid":
		return true
	}
	return false
}

// stringLit returns the unquoted value of a string-literal expression.
func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil || v == "" {
		return "", false
	}
	return v, true
}
