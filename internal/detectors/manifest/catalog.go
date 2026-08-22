package manifest

import (
	"strings"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
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
		"langchain":           {kFramework, provLangChain, ""},
		"langchain-core":      {kFramework, provLangChain, ""},
		"langchain-community": {kFramework, provLangChain, ""},
		"llama-index":         {kFramework, provLlamaIdx, ""},
		"haystack-ai":         {kFramework, provDeepset, ""},
		"dspy-ai":             {kFramework, "dspy", ""},
		"crewai":              {kFramework, "crewai", ""},
		// The provider on these must match the slug their rule pack claims.
		// The assembler folds a manifest sighting into a code sighting by
		// (provider, name), so leaving it empty here — as several older
		// entries do — reports the dependency and its usage as two components.
		"agno":         {kFramework, "agno", ""},
		"phidata":      {kFramework, "agno", ""}, // agno's former name; still pinned in older projects
		"crawl4ai":     {kFramework, "crawl4ai", ""},
		"firecrawl":    {kFramework, "firecrawl", ""},
		"firecrawl-py": {kFramework, "firecrawl", "firecrawl"},
		// fastmcp 3.x is a metapackage: the module ships in fastmcp-slim, so an
		// installed-metadata or lockfile scan sees both names.
		"fastmcp":      {kFramework, "fastmcp", ""},
		"fastmcp-slim": {kFramework, "fastmcp", ""},
		// The provider must match the slug the mcp rule pack claims. It was left
		// empty here because no EMBEDDED pack claims mcp — but the signed bundle
		// ships one, so bundle users got the dependency and its usage as two
		// separate components. The cross-check test only reads embedded packs,
		// which is exactly why it did not catch this.
		"mcp": {kFramework, "mcp", ""}, // the official Model Context Protocol SDK
		// ── Agent and application frameworks ───────────────────────────────
		"camel-ai":         {kFramework, "camel-ai", "camel"}, // imports as `camel`
		"metagpt":          {kFramework, "metagpt", ""},
		"langroid":         {kFramework, "langroid", ""},
		"llmware":          {kFramework, "llmware", ""},
		"txtai":            {kFramework, "txtai", ""},
		"gpt-researcher":   {kFramework, "gpt-researcher", ""},
		"open-interpreter": {kFramework, "open-interpreter", ""},
		"letta":            {kFramework, "letta", ""},
		"memgpt":           {kFramework, "letta", ""}, // MemGPT's former name; frozen at 0.2.0
		"mindsdb":          {kFramework, "mindsdb", ""},
		"ludwig":           {kFramework, "ludwig", ""},

		// ── Local inference runtimes ───────────────────────────────────────
		"llama-cpp-python": {kFramework, "llama-cpp", "llama-cpp"}, // imports as `llama_cpp`
		"gpt4all":          {kFramework, "nomic", ""},
		"exllamav2":        {kFramework, "exllama", ""},
		"fschat":           {kFramework, "lmsys", ""},
		"ollama":           {kLibrary, provOllama, ""},

		// ── Training and finetuning ────────────────────────────────────────
		"deepspeed":  {kFramework, provMicrosoft, ""},
		"unsloth":    {kFramework, "unsloth", ""},
		"colossalai": {kFramework, "colossalai", ""},

		// ── LLM observability ──────────────────────────────────────────────
		"lunary": {kLibrary, "lunary", ""},

		"pyautogen":             {kFramework, provMicrosoft, ""},
		"autogen":               {kFramework, provMicrosoft, ""},
		"semantic-kernel":       {kFramework, provMicrosoft, ""},
		"transformers":          {kFramework, provHF, ""},
		"sentence-transformers": {kLibrary, provHF, ""},
		"torch":                 {kFramework, "PyTorch", ""},
		"tensorflow":            {kFramework, provGoogle, ""},
		"vllm":                  {kFramework, "vllm", ""},
		"mlflow":                {kFramework, "mlflow", ""},
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
		"deeplake":              {kVectorDB, "activeloop", ""},
		"pgvector":              {kVectorDB, "pgvector", ""},
	},
	prefixes: []prefixRule{
		{"langchain-", aiPkg{kFramework, provLangChain, ""}},
	},
}

// LookupPyPI resolves a PyPI distribution name to the AI identity AIROM
// attributes to it, reporting ok=false for everything outside the curated
// catalog.
//
// Exported because the catalog is the line between an AIBOM and an SBOM, and
// more than one detector needs to stand on it. A frozen executable has no
// manifest and no metadata — its module list is all there is — but "crawl4ai"
// means the same thing there as in a requirements.txt, and an ungated module
// list would inventory every top-level package a 197 MB binary happens to
// bundle.
func LookupPyPI(name string) (kind airom.ComponentKind, provider, canonical string, ok bool) {
	key := normalizePyPI(name)
	p, found := pypiCatalog.lookup(key)
	if !found {
		return "", "", "", false
	}
	return p.kind, p.provider, p.emitName(key), true
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
		"@modelcontextprotocol/sdk":   {kFramework, "", ""},
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
		"azure.ai.openai": {kLibrary, provMicrosoft, "Azure.AI.OpenAI"},
		"openai":          {kLibrary, provOpenAI, "OpenAI"},
		// Display name folds with the rule pack's claim ("semantic-kernel");
		// the declared NuGet identity travels in the purl. Split-brain found
		// by airom-bench Tier S.
		"microsoft.semantickernel": {kFramework, provMicrosoft, "semantic-kernel"},
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
	case group == "com.aallam.openai":
		// The de facto Kotlin OpenAI SDK (openai-client, openai-core).
		// Absence found by airom-bench Tier S: a build.gradle.kts declaring
		// it produced zero components (airomhq/airom#17).
		return aiPkg{kLibrary, provOpenAI, ""}, true
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

// mkFindingSpec builds one manifest finding from a raw declared specifier,
// routing it to Version or VersionConstraint per the ecosystem's bare-version
// semantics (see versionSpec). Detectors that already hold a resolved version
// — lockfiles, installed metadata, go.mod — call mkFinding directly.
func mkFindingSpec(p aiPkg, name, group, ecosystem, spec string, bareIsExact bool, line int) detect.Finding {
	version, constraint := versionSpec(spec, bareIsExact)
	f := mkFinding(p, name, group, ecosystem, version, line)
	f.Claim.VersionConstraint = constraint
	return f
}
