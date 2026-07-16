package manifest

import (
	"strings"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// confDeclared is the per-sighting confidence for a declared dependency: a
// manifest names an exact package identity, so the evidence is strong but
// never certain (the assembler reserves 1.0 for hash/attestation).
const confDeclared = airom.Confidence(0.95)

// aiPkg is one row of the curated AI-package knowledge table: the kind and
// provider AIROM attributes to a recognized dependency. canon overrides the
// emitted component name; empty canon emits the (normalized) declared name.
type aiPkg struct {
	kind     airom.ComponentKind
	provider string
	canon    string
}

// prefixRule matches a family of package names by a shared prefix (e.g.
// every "langchain-*" or "@langchain/*" package).
type prefixRule struct {
	prefix string
	pkg    aiPkg
}

// catalog resolves a declared package name to an aiPkg. Exact hits win;
// prefixes are tried in declared order (kept non-overlapping) only on miss.
type catalog struct {
	exact    map[string]aiPkg
	prefixes []prefixRule
}

// lookup resolves key to its knowledge-table row. key must already be
// normalized for the ecosystem (see normalizePyPI / lowercasing).
func (c catalog) lookup(key string) (aiPkg, bool) {
	if p, ok := c.exact[key]; ok {
		return p, true
	}
	for _, r := range c.prefixes {
		if strings.HasPrefix(key, r.prefix) {
			return r.pkg, true
		}
	}
	return aiPkg{}, false
}

// emitName picks the component name: the curated canonical when set,
// otherwise the (already normalized) declared name.
func (p aiPkg) emitName(declared string) string {
	if p.canon != "" {
		return p.canon
	}
	return declared
}

// ── Provider constants (canonical vendor labels shared across ecosystems) ──

const (
	provOpenAI    = "OpenAI"
	provAnthropic = "Anthropic"
	provGoogle    = "Google"
	provCohere    = "Cohere"
	provMistral   = "Mistral AI"
	provGroq      = "Groq"
	provLangChain = "LangChain"
	provLlamaIdx  = "LlamaIndex"
	provHF        = "Hugging Face"
	provPinecone  = "Pinecone"
	provQdrant    = "Qdrant"
	provWeaviate  = "Weaviate"
	provChroma    = "Chroma"
	provMeta      = "Meta"
	provMilvus    = "Milvus"
	provMicrosoft = "Microsoft"
	provOllama    = "Ollama"
	provVoyage    = "Voyage AI"
	provDeepset   = "deepset"
)

// kinds reused throughout the tables.
const (
	kFramework = airom.KindFramework
	kLibrary   = airom.KindLibrary
	kVectorDB  = airom.KindVectorDB
)

// ── PyPI (pip / requirements / pyproject) ──────────────────────────────────

// normalizePyPI applies PEP 503 name normalization: lowercase and collapse
// runs of "-", "_", "." to a single "-". So "LLaMa_Index" == "llama-index".
func normalizePyPI(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	b.Grow(len(name))
	prevDash := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '-' || c == '_' || c == '.' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteByte(c)
		prevDash = false
	}
	return strings.Trim(b.String(), "-")
}

var pypiCatalog = catalog{
	exact: map[string]aiPkg{
		"langchain":             {kFramework, provLangChain, ""},
		"langchain-core":        {kFramework, provLangChain, ""},
		"langchain-community":   {kFramework, provLangChain, ""},
		"llama-index":           {kFramework, provLlamaIdx, ""},
		"haystack-ai":           {kFramework, provDeepset, ""},
		"dspy-ai":               {kFramework, "", ""},
		"crewai":                {kFramework, "", ""},
		"pyautogen":             {kFramework, provMicrosoft, ""},
		"autogen":               {kFramework, provMicrosoft, ""},
		"semantic-kernel":       {kFramework, provMicrosoft, ""},
		"transformers":          {kFramework, provHF, ""},
		"sentence-transformers": {kLibrary, provHF, ""},
		"torch":                 {kFramework, "PyTorch", ""},
		"tensorflow":            {kFramework, provGoogle, ""},
		"vllm":                  {kFramework, "", ""},
		"mlflow":                {kFramework, "", ""},
		"guidance":              {kFramework, "", ""},
		"outlines":              {kFramework, "", ""},
		"onnxruntime":           {kLibrary, provMicrosoft, ""},
		"openai":                {kLibrary, provOpenAI, ""},
		"tiktoken":              {kLibrary, provOpenAI, ""},
		"anthropic":             {kLibrary, provAnthropic, ""},
		"google-generativeai":   {kLibrary, provGoogle, ""},
		"google-genai":          {kLibrary, provGoogle, ""},
		"cohere":                {kLibrary, provCohere, ""},
		"mistralai":             {kLibrary, provMistral, ""},
		"groq":                  {kLibrary, provGroq, ""},
		"voyageai":              {kLibrary, provVoyage, ""},
		"instructor":            {kLibrary, "", ""},
		"litellm":               {kLibrary, "", ""},
		"chromadb":              {kVectorDB, provChroma, ""},
		"pinecone-client":       {kVectorDB, provPinecone, ""},
		"qdrant-client":         {kVectorDB, provQdrant, ""},
		"weaviate-client":       {kVectorDB, provWeaviate, ""},
		"faiss-cpu":             {kVectorDB, provMeta, ""},
		"faiss-gpu":             {kVectorDB, provMeta, ""},
		"pymilvus":              {kVectorDB, provMilvus, ""},
		"redis":                 {kVectorDB, "Redis", ""},
		"pgvector":              {kVectorDB, "", ""},
	},
	prefixes: []prefixRule{
		{"langchain-", aiPkg{kFramework, provLangChain, ""}},
	},
}

// ── npm (package.json) ─────────────────────────────────────────────────────

var npmCatalog = catalog{
	exact: map[string]aiPkg{
		"openai":                      {kLibrary, provOpenAI, ""},
		"@anthropic-ai/sdk":           {kLibrary, provAnthropic, ""},
		"@google/generative-ai":       {kLibrary, provGoogle, ""},
		"langchain":                   {kFramework, provLangChain, ""},
		"llamaindex":                  {kFramework, provLlamaIdx, ""},
		"ai":                          {kLibrary, "Vercel", ""},
		"cohere-ai":                   {kLibrary, provCohere, ""},
		"@mistralai/mistralai":        {kLibrary, provMistral, ""},
		"groq-sdk":                    {kLibrary, provGroq, ""},
		"@pinecone-database/pinecone": {kVectorDB, provPinecone, ""},
		"chromadb":                    {kVectorDB, provChroma, ""},
		"@qdrant/js-client-rest":      {kVectorDB, provQdrant, ""},
		"weaviate-ts-client":          {kVectorDB, provWeaviate, ""},
		"onnxruntime-node":            {kLibrary, provMicrosoft, ""},
		"@xenova/transformers":        {kFramework, provHF, ""},
	},
	prefixes: []prefixRule{
		{"@langchain/", aiPkg{kFramework, provLangChain, ""}},
	},
}

// ── Go modules (go.mod) ────────────────────────────────────────────────────

var goCatalog = catalog{
	exact: map[string]aiPkg{
		"github.com/sashabaranov/go-openai":  {kLibrary, provOpenAI, ""},
		"github.com/tmc/langchaingo":         {kFramework, provLangChain, ""},
		"github.com/philippgille/chromem-go": {kVectorDB, provChroma, ""},
		"github.com/pinecone-io/go-pinecone": {kVectorDB, provPinecone, ""},
		"github.com/qdrant/go-client":        {kVectorDB, provQdrant, ""},
		"github.com/milvus-io/milvus-sdk-go": {kVectorDB, provMilvus, ""},
		"github.com/ollama/ollama":           {kLibrary, provOllama, ""},
	},
}

// ── Cargo (Cargo.toml) ─────────────────────────────────────────────────────

var cargoCatalog = catalog{
	exact: map[string]aiPkg{
		"async-openai":   {kLibrary, provOpenAI, ""},
		"langchain-rust": {kFramework, provLangChain, ""},
		"qdrant-client":  {kVectorDB, provQdrant, ""},
		"candle-core":    {kFramework, provHF, ""},
		"ort":            {kLibrary, provMicrosoft, ""},
		"tokenizers":     {kLibrary, provHF, ""},
	},
}

// ── NuGet (*.csproj) ───────────────────────────────────────────────────────
//
// NuGet package IDs are case-insensitive; keys are lowercased and canon
// restores the conventional casing.
var nugetCatalog = catalog{
	exact: map[string]aiPkg{
		"azure.ai.openai":          {kLibrary, provMicrosoft, "Azure.AI.OpenAI"},
		"openai":                   {kLibrary, provOpenAI, "OpenAI"},
		"microsoft.semantickernel": {kFramework, provMicrosoft, "Microsoft.SemanticKernel"},
		"langchain":                {kFramework, provLangChain, "LangChain"},
		"betalgo.openai":           {kLibrary, provOpenAI, "Betalgo.OpenAI"},
		"pinecone.net":             {kVectorDB, provPinecone, "Pinecone.NET"},
	},
}

// mavenLookup resolves a Maven groupId:artifactId coordinate. Maven identity
// is the (group, artifact) pair, so it gets a dedicated resolver rather than
// a flat name catalog.
func mavenLookup(group, artifact string) (aiPkg, bool) {
	switch {
	case group == "dev.langchain4j":
		return aiPkg{kFramework, provLangChain, ""}, true
	case strings.HasPrefix(group, "com.theokanning.openai-gpt3-java"):
		return aiPkg{kLibrary, provOpenAI, ""}, true
	case group == "io.milvus" && artifact == "milvus-sdk-java":
		return aiPkg{kVectorDB, provMilvus, ""}, true
	}
	return aiPkg{}, false
}

// ── Shared finding construction ────────────────────────────────────────────

// mkFinding builds one manifest finding. Path, DetectorID, and Snippet are
// left for the engine to fill; Line is 1-based (the dependency's own line).
func mkFinding(p aiPkg, name, group, ecosystem string, version string, line int) detect.Finding {
	return detect.Finding{
		Claim: detect.ComponentClaim{
			Kind:     p.kind,
			Name:     name,
			Group:    group,
			Version:  version,
			Provider: p.provider,
			Package:  &detect.PackageClaim{Ecosystem: ecosystem},
		},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Line: line},
			Method:     airom.MethodManifest,
			Confidence: confDeclared,
		},
	}
}
