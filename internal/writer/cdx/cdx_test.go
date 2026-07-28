package cdx

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

var update = flag.Bool("update", false, "update golden files")

// Component IDs, chosen to sort lexicographically in this order (Components
// arrive sorted by ID, per the Inventory contract).
const (
	idRoot    = airom.ID("airom:0000000000000000")
	idHosted  = airom.ID("airom:1111111111111111")
	idLocal   = airom.ID("airom:2222222222222222")
	idFramew  = airom.ID("airom:3333333333333333")
	idDataset = airom.ID("airom:4444444444444444")
	idPrompt  = airom.ID("airom:5555555555555555")
	idConfig  = airom.ID("airom:6666666666666666")
	idVecDB   = airom.ID("airom:7777777777777777")
)

const sha256Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fixtureInventory builds a representative inventory exercising every mapping
// row the writer implements: a hosted-llm (occurrences + contested identity +
// bound params + full card), a local-model-file (hash + pickle risk +
// trained-on), a framework (version + purl + depends-on), a dataset, a prompt,
// an ai-config (unbound param via Props), a vector-db (airom:rel edge), plus
// Unknowns and the application root.
func fixtureInventory() *airom.Inventory {
	ts := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rel := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)

	root := airom.Component{
		ID:         idRoot,
		Kind:       airom.KindApplication,
		Name:       "my-rag-app",
		Confidence: 0.95,
		Evidence: airom.Evidence{
			// Whole-file sighting: line 0 must omit the CDX line field.
			Occurrences: []airom.Occurrence{{
				Location:   airom.Location{Path: "pyproject.toml", Line: 0},
				DetectorID: "rules/python/project",
				Method:     airom.MethodConfig,
				Confidence: 0.95,
			}},
		},
	}

	hosted := airom.Component{
		ID:         idHosted,
		Kind:       airom.KindHostedLLM,
		Name:       "gpt-4.1",
		Group:      "openai",
		Provider:   airom.KnownString("openai"),
		Confidence: 0.9,
		Model: &airom.ModelFacet{
			Task: airom.KnownString("text-generation"),
			GenerationParams: []airom.BoundParam{{
				Name:  "temperature",
				Value: "0.2",
				Occurrence: &airom.Occurrence{
					Location: airom.Location{Path: "src/rag.py", Line: 42},
				},
			}},
			Card: &airom.ModelCard{
				Metrics: []airom.PerformanceMetric{{Type: "accuracy", Value: "0.92", Slice: "test"}},
				Considerations: &airom.Considerations{
					Users:                []string{"analysts"},
					UseCases:             []string{"summarization"},
					TechnicalLimitations: []string{"bounded context window"},
				},
				Energy: []airom.EnergyConsumption{{Activity: "inference", KWh: 0.5}},
			},
		},
		// Raw provider-native id has no dedicated domain field; it rides in
		// Props verbatim (§3.2 overflow → airom:model.id).
		Props: []airom.KV{{Name: "airom:model.id", Value: "gpt-4.1-2026-01-14"}},
		// EOL overlay: projects as airom:eol.* component properties, NOT a
		// vulnerabilities[] entry — a scheduled retirement is not a defect.
		EOL: &airom.Lifecycle{
			State:            airom.EOLDeprecated,
			Announced:        &airom.Date{Year: 2026, Month: 4, Day: 22},
			Shutdown:         &airom.Date{Year: 2026, Month: 10, Day: 23},
			DaysRemaining:    func() *int { d := 99; return &d }(),
			Replacement:      "gpt-4.2",
			ReplacementState: airom.EOLRetired,
			Source:           "airom-catalog",
			SourceURL:        "https://example.com/deprecations",
			Verified:         &airom.Date{Year: 2026, Month: 7, Day: 16},
		},
		Evidence: airom.Evidence{
			Occurrences: []airom.Occurrence{{
				Location:   airom.Location{Path: "src/rag.py", Line: 42},
				DetectorID: "rules/openai/model-literal",
				Method:     airom.MethodSourceCode,
				Confidence: 0.9,
				Snippet:    `model="gpt-4.1"`,
				Symbol:     "build_chain",
			}},
			Identity: []airom.IdentityClaim{
				{Field: "name", Value: "gpt-4.1", Confidence: 0.9, Methods: []airom.DetectionMethod{airom.MethodSourceCode}},
				// Losing claim from config-analysis: technique "other" + value marker.
				{Field: "name", Value: "gpt-4", Confidence: 0.3, Methods: []airom.DetectionMethod{airom.MethodConfig}},
			},
		},
	}

	local := airom.Component{
		ID:               idLocal,
		Kind:             airom.KindLocalModelFile,
		Name:             "llama-3-8b.Q4_K_M.gguf",
		Provider:         airom.KnownString("local"),
		PURL:             "pkg:generic/llama-3-8b?checksum=sha256:" + sha256Hex,
		DownloadLocation: airom.KnownString("https://huggingface.co/meta/llama-3-8b/resolve/main/model.gguf"),
		ReleaseTime:      airom.KnownTime(rel),
		Hashes: []airom.Hash{
			{Alg: "SHA-256", Hex: sha256Hex},
			{Alg: "XXH3", Hex: "deadbeefdeadbeef"}, // cache-internal → dropped
		},
		Attestations: []airom.AttestationRef{{
			Type:     "sigstore-bundle",
			URI:      "https://example.com/attestation.json",
			Verified: airom.TriUnknown,
		}},
		Confidence: 1.0,
		Model: &airom.ModelFacet{
			Architecture:  airom.KnownString("llama"),
			Format:        airom.KnownString("gguf"),
			ParamCount:    airom.KnownInt64(8030261248),
			Quantization:  airom.KnownString("Q4_K_M"),
			ContextLength: airom.KnownInt64(8192),
		},
		Risks: []airom.ArtifactRisk{{
			ID: airom.RiskPickleImport, Severity: airom.RiskHigh,
			Detail:     []string{"builtins.eval", "os.system"},
			Occurrence: &airom.Occurrence{Location: airom.Location{Path: "models/llama.gguf"}, DetectorID: "modelfilex/torch", Method: airom.MethodBinary, Confidence: 0.95},
		}},
		Evidence: airom.Evidence{
			Occurrences: []airom.Occurrence{{
				Location:   airom.Location{Path: "models/llama.gguf", Line: 0},
				DetectorID: "rules/gguf/header",
				Method:     airom.MethodBinary,
				Confidence: 1.0,
				Snippet:    "GGUF",
			}},
			Identity: []airom.IdentityClaim{
				{Field: "hash", Value: sha256Hex, Confidence: 1.0, Methods: []airom.DetectionMethod{airom.MethodHash}},
			},
		},
	}

	framework := airom.Component{
		ID:         idFramew,
		Kind:       airom.KindFramework,
		Name:       "langchain",
		Version:    airom.KnownString("0.2.1"),
		PURL:       "pkg:pypi/langchain@0.2.1",
		Licenses:   []airom.License{{SPDXID: "MIT"}},
		Supplier:   &airom.Party{Name: "LangChain, Inc.", URL: "https://langchain.com"},
		SourceInfo: "declared in requirements.txt",
		Confidence: 0.95,
		Package:    &airom.PackageFacet{Ecosystem: "pypi"},
		// CVE overlay: one advisory with a CVSS v3.1 vector/score, an alias, and a
		// fixed version, so the golden pins the vulnerabilities[] projection.
		Vulnerabilities: []airom.Vulnerability{{
			ID: "CVE-2024-0001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
			Severity: airom.VulnHigh, Score: 7.5,
			Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Summary: "Server-side request forgery in the example loader.",
			Fixed:   "0.2.5", Source: "osv.dev",
			URL: "https://osv.dev/vulnerability/CVE-2024-0001",
		}},
		Evidence: airom.Evidence{
			Occurrences: []airom.Occurrence{{
				Location:   airom.Location{Path: "requirements.txt", Line: 3},
				DetectorID: "rules/pypi/requirement",
				Method:     airom.MethodManifest,
				Confidence: 0.95,
				Snippet:    "langchain==0.2.1",
			}},
			Identity: []airom.IdentityClaim{
				{Field: "version", Value: "0.2.1", Confidence: 0.95, Methods: []airom.DetectionMethod{airom.MethodManifest}},
			},
		},
	}

	dataset := airom.Component{
		ID:         idDataset,
		Kind:       airom.KindDataset,
		Name:       "wikitext-103",
		Confidence: 0.8,
		Data: &airom.DataFacet{
			Format:    airom.KnownString("parquet"),
			SizeBytes: airom.KnownInt64(524288000),
			URL:       airom.KnownString("https://huggingface.co/datasets/wikitext"),
		},
		Evidence: airom.Evidence{
			Occurrences: []airom.Occurrence{{
				Location:   airom.Location{Path: "train.py", Line: 12},
				DetectorID: "rules/hf/dataset",
				Method:     airom.MethodSourceCode,
				Confidence: 0.8,
			}},
		},
	}

	prompt := airom.Component{
		ID:         idPrompt,
		Kind:       airom.KindPrompt,
		Name:       "system-prompt",
		Confidence: 0.7,
		Data:       &airom.DataFacet{},
		Evidence: airom.Evidence{
			Occurrences: []airom.Occurrence{{
				Location:   airom.Location{Path: "prompts/system.txt", Line: 1},
				DetectorID: "rules/prompt/file",
				Method:     airom.MethodFilename,
				Confidence: 0.7,
			}},
		},
	}

	aiconfig := airom.Component{
		ID:         idConfig,
		Kind:       airom.KindAIConfig,
		Name:       "generation.yaml",
		Confidence: 0.85,
		Data:       &airom.DataFacet{},
		// Unbound generation param on an ai-config rides in Props (§3.7).
		Props: []airom.KV{{Name: "airom:param.top_p", Value: "0.9 @ config/generation.yaml:5"}},
		Evidence: airom.Evidence{
			Occurrences: []airom.Occurrence{{
				Location:   airom.Location{Path: "config/generation.yaml", Line: 5},
				DetectorID: "rules/config/generation",
				Method:     airom.MethodConfig,
				Confidence: 0.85,
			}},
		},
	}

	vecdb := airom.Component{
		ID:         idVecDB,
		Kind:       airom.KindVectorDB,
		Name:       "pinecone",
		Confidence: 0.75,
		Evidence: airom.Evidence{
			Occurrences: []airom.Occurrence{{
				Location:   airom.Location{Path: "src/store.py", Line: 8},
				DetectorID: "rules/vectordb/pinecone",
				Method:     airom.MethodSourceCode,
				Confidence: 0.75,
			}},
		},
	}

	return &airom.Inventory{
		SchemaVersion: "1",
		Tool:          airom.ToolInfo{Name: "airom", Version: "1.0.0", Commit: "abc123def456"},
		Serial:        "11111111-2222-3333-4444-555555555555",
		Timestamp:     ts,
		Lifecycle:     "pre-build",
		Source: airom.SourceInfo{
			Kind:   "repo",
			Target: "https://github.com/example/rag-app",
			Git: &airom.GitInfo{
				Remote: "https://github.com/example/rag-app.git",
				Commit: "deadbeefcafe",
				Dirty:  false,
			},
		},
		Root: idRoot,
		// Sorted by ID (deterministic, P7).
		Components: []airom.Component{root, hosted, local, framework, dataset, prompt, aiconfig, vecdb},
		Relationships: []airom.Relationship{
			{From: idRoot, Type: airom.RelDependsOn, To: idFramew, Confidence: 0.95},
			{From: idLocal, Type: airom.RelTrainedOn, To: idDataset, Confidence: 0.9},
			{From: idVecDB, Type: airom.RelUses, To: idHosted, Confidence: 0.9},
		},
		Unknowns: []airom.Unknown{
			{Path: "models/mystery.bin", DetectorID: "rules/gguf/header", Reason: "unrecognized magic bytes"},
		},
		// Compliance overlay: met (evidence), gap (counter), and manual (no
		// score) so the golden pins the full definitions/declarations shape.
		Compliance: []airom.ComplianceResult{{
			Framework: "nist-ai-rmf",
			Name:      "NIST AI Risk Management Framework",
			Version:   "1.0",
			URL:       "https://www.nist.gov/itl/ai-risk-management-framework",
			Controls: []airom.ControlOutcome{
				{
					ID: "MAP-2.1", Title: "AI methods are inventoried and documented", Ref: "https://airc.nist.gov/",
					State: airom.ControlMet, Score: &scoreOne, Rationale: "2 component(s) provide supporting evidence",
					Evidence: []airom.ID{idHosted, idFramew},
				},
				{
					ID: "MEASURE-2.7", Title: "AI system security and resilience are evaluated",
					State: airom.ControlGap, Score: &scoreZero, Rationale: "1 component(s) constitute a gap",
					Counter: []airom.ID{idLocal},
				},
				{
					ID: "GOVERN-1.1", Title: "Legal and regulatory requirements are documented",
					State: airom.ControlManual, Rationale: "not automatable by a static scan — requires manual attestation",
				},
			},
		}},
	}
}

var (
	scoreOne  = 1.0
	scoreZero = 0.0
)

func encode(t *testing.T, opts writer.Options) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := New(opts)
	if got := w.Format(); got != "cyclonedx" {
		t.Fatalf("Format() = %q, want cyclonedx", got)
	}
	if err := w.Write(&buf, fixtureInventory()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.Bytes()
}

func TestEncodesAndReparses(t *testing.T) {
	raw := encode(t, writer.Options{})

	var bom cyclonedx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	// Envelope.
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q", bom.BOMFormat)
	}
	if bom.SpecVersion != cyclonedx.SpecVersion1_6 {
		t.Errorf("specVersion = %v, want 1.6", bom.SpecVersion)
	}
	if bom.SerialNumber != "urn:uuid:11111111-2222-3333-4444-555555555555" {
		t.Errorf("serialNumber = %q", bom.SerialNumber)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("metadata.component missing")
	}

	// Root is metadata.component and NOT duplicated in components[].
	if bom.Metadata.Component.BOMRef != string(idRoot) {
		t.Errorf("metadata.component bom-ref = %q, want root", bom.Metadata.Component.BOMRef)
	}
	if _, ok := propVal(bom.Metadata.Component.Properties, "airom:kind"); !ok {
		t.Error("root metadata.component missing airom:kind")
	}
	comps := derefComponents(bom.Components)
	if findComp(comps, string(idRoot)) != nil {
		t.Error("root duplicated in components[]")
	}
	if len(comps) != 7 {
		t.Errorf("components len = %d, want 7 (8 minus root)", len(comps))
	}

	// Every component carries airom:kind + airom:confidence.
	for i := range comps {
		c := &comps[i]
		if _, ok := propVal(c.Properties, "airom:kind"); !ok {
			t.Errorf("%s missing airom:kind", c.BOMRef)
		}
		if _, ok := propVal(c.Properties, "airom:confidence"); !ok {
			t.Errorf("%s missing airom:confidence", c.BOMRef)
		}
	}

	// Model kinds have a modelCard; non-model kinds never do.
	for i := range comps {
		c := &comps[i]
		isModel := c.Type == cyclonedx.ComponentTypeMachineLearningModel
		if isModel && c.ModelCard == nil {
			t.Errorf("%s is ML type but has no modelCard", c.BOMRef)
		}
		if !isModel && c.ModelCard != nil {
			t.Errorf("%s is %s but has a modelCard", c.BOMRef, c.Type)
		}
	}

	// Metadata properties: source + unknown count.
	if v, ok := propVal(bom.Metadata.Properties, "airom:source.type"); !ok || v != "repo" {
		t.Errorf("airom:source.type = %q,%v", v, ok)
	}
	if v, ok := propVal(bom.Metadata.Properties, "airom:unknowns"); !ok || v != "1" {
		t.Errorf("airom:unknowns = %q,%v; want 1", v, ok)
	}
	if v, ok := propVal(bom.Metadata.Properties, "airom:tool.commit"); !ok || v != "abc123def456" {
		t.Errorf("airom:tool.commit = %q,%v", v, ok)
	}

	// Hosted-llm: no purl, model.provider + model.id, bound param, contested id.
	hosted := findComp(comps, string(idHosted))
	if hosted == nil {
		t.Fatal("hosted-llm missing")
	}
	if hosted.PackageURL != "" {
		t.Errorf("hosted-llm purl = %q, want empty (hosted models get no purl)", hosted.PackageURL)
	}
	if v, ok := propVal(hosted.Properties, "airom:model.provider"); !ok || v != "openai" {
		t.Errorf("airom:model.provider = %q,%v", v, ok)
	}
	if v, ok := propVal(hosted.Properties, "airom:model.id"); !ok || v != "gpt-4.1-2026-01-14" {
		t.Errorf("airom:model.id passthrough = %q,%v", v, ok)
	}
	if v, ok := propVal(hosted.Properties, "airom:param.temperature"); !ok || v != "0.2 @ src/rag.py:42" {
		t.Errorf("airom:param.temperature = %q,%v", v, ok)
	}
	// Occurrence carries file:line.
	if hosted.Evidence == nil || hosted.Evidence.Occurrences == nil {
		t.Fatal("hosted-llm evidence.occurrences missing")
	}
	occ := (*hosted.Evidence.Occurrences)[0]
	if occ.Location != "src/rag.py" || occ.Line == nil || *occ.Line != 42 {
		t.Errorf("occurrence = %q line=%v, want src/rag.py:42", occ.Location, occ.Line)
	}
	// Contested identity: losing config-analysis claim → technique "other" + value marker.
	if hosted.Evidence.Identity == nil || hosted.Evidence.Identity.Identities == nil {
		t.Fatal("hosted-llm evidence.identity missing")
	}
	foundConfigMarker := false
	for _, id := range *hosted.Evidence.Identity.Identities {
		if id.ConcludedValue == "gpt-4" && id.Methods != nil {
			for _, m := range *id.Methods {
				if m.Technique == cyclonedx.EvidenceIdentityTechniqueOther && m.Value == "config-analysis" {
					foundConfigMarker = true
				}
			}
		}
	}
	if !foundConfigMarker {
		t.Error("config-analysis method not mapped to technique=other, value=config-analysis")
	}

	// hosted-llm modelCard: task + metrics + considerations + energy(kWh).
	mc := hosted.ModelCard
	if mc == nil || mc.ModelParameters == nil || mc.ModelParameters.Task != "text-generation" {
		t.Fatalf("hosted modelCard.task missing: %+v", mc)
	}
	if mc.QuantitativeAnalysis == nil || mc.QuantitativeAnalysis.PerformanceMetrics == nil {
		t.Error("hosted modelCard metrics missing")
	}
	if mc.Considerations == nil || mc.Considerations.EnvironmentalConsiderations == nil {
		t.Fatal("hosted modelCard energy missing")
	}
	ec := (*mc.Considerations.EnvironmentalConsiderations.EnergyConsumptions)[0]
	if ec.ActivityEnergyCost.Unit != cyclonedx.MLModelEnergyUnitKWH {
		t.Errorf("energy unit = %q, want kWh", ec.ActivityEnergyCost.Unit)
	}

	// Local-model-file: SHA-256-only hash, pickle props, distribution+attestation refs.
	local := findComp(comps, string(idLocal))
	if local == nil {
		t.Fatal("local-model-file missing")
	}
	if local.Hashes == nil || len(*local.Hashes) != 1 || (*local.Hashes)[0].Algorithm != cyclonedx.HashAlgoSHA256 {
		t.Errorf("local hashes = %+v, want single SHA-256", local.Hashes)
	}
	if v, ok := propVal(local.Properties, "airom:pickle.imports"); !ok || v != "builtins.eval|os.system" {
		t.Errorf("airom:pickle.imports = %q,%v", v, ok)
	}
	if _, ok := propVal(local.Properties, "airom:releaseTime"); !ok {
		t.Error("local missing airom:releaseTime")
	}
	if !hasExtRef(local.ExternalReferences, cyclonedx.ERTypeDistribution) {
		t.Error("local missing distribution externalReference")
	}
	if !hasExtRef(local.ExternalReferences, cyclonedx.ERTypeAttestation) {
		t.Error("local missing attestation externalReference")
	}
	// Whole-file occurrence omits line.
	if local.Evidence == nil || (*local.Evidence.Occurrences)[0].Line != nil {
		t.Error("local whole-file occurrence should omit line")
	}
	// trained-on became modelCard datasets ref.
	if local.ModelCard == nil || local.ModelCard.ModelParameters == nil || local.ModelCard.ModelParameters.Datasets == nil {
		t.Fatal("local modelCard datasets missing (trained-on edge)")
	}
	if ref := (*local.ModelCard.ModelParameters.Datasets)[0].Ref; ref != string(idDataset) {
		t.Errorf("datasets[0].ref = %q, want dataset id", ref)
	}

	// depends-on became a dependencies[] entry rooted at the app.
	if bom.Dependencies == nil {
		t.Fatal("dependencies[] missing")
	}
	foundDep := false
	for _, d := range *bom.Dependencies {
		if d.Ref == string(idRoot) && d.Dependencies != nil {
			for _, on := range *d.Dependencies {
				if on == string(idFramew) {
					foundDep = true
				}
			}
		}
	}
	if !foundDep {
		t.Error("depends-on (root→framework) not in dependencies[]")
	}

	// artifact risk became a vulnerabilities[] entry affecting the model file.
	if bom.Vulnerabilities == nil {
		t.Fatal("vulnerabilities[] missing")
	}
	var vuln *cyclonedx.Vulnerability
	for i := range *bom.Vulnerabilities {
		if (*bom.Vulnerabilities)[i].ID == "AIROM-RISK-PICKLE-IMPORT" {
			vuln = &(*bom.Vulnerabilities)[i]
		}
	}
	if vuln == nil {
		t.Fatal("AIROM-RISK-PICKLE-IMPORT vulnerability missing")
	}
	if vuln.Source == nil || vuln.Source.Name != "airom" {
		t.Errorf("vuln source = %+v, want airom", vuln.Source)
	}
	if vuln.Ratings == nil || (*vuln.Ratings)[0].Severity != cyclonedx.SeverityHigh || (*vuln.Ratings)[0].Method != cyclonedx.ScoringMethodOther {
		t.Errorf("vuln rating = %+v, want high/other", vuln.Ratings)
	}
	if vuln.Affects == nil || (*vuln.Affects)[0].Ref != string(idLocal) {
		t.Errorf("vuln affects = %+v, want the model-file ref", vuln.Affects)
	}
	if v, ok := propVal(vuln.Properties, "airom:risk.symbols"); !ok || v != "builtins.eval|os.system" {
		t.Errorf("vuln airom:risk.symbols = %q,%v", v, ok)
	}

	// vector-db airom:rel.* edge.
	vecdb := findComp(comps, string(idVecDB))
	if v, ok := propVal(vecdb.Properties, "airom:rel.uses"); !ok || v != string(idHosted)+"@0.9" {
		t.Errorf("airom:rel.uses = %q,%v", v, ok)
	}

	// dataset data facet: type + contents url + props.
	dataset := findComp(comps, string(idDataset))
	if dataset.Data == nil || (*dataset.Data)[0].Type != cyclonedx.ComponentDataTypeDataset {
		t.Error("dataset data[].type != dataset")
	}
	if (*dataset.Data)[0].Contents == nil || (*dataset.Data)[0].Contents.URL == "" {
		t.Error("dataset data[].contents.url missing")
	}

	// ai-config param passthrough.
	cfg := findComp(comps, string(idConfig))
	if v, ok := propVal(cfg.Properties, "airom:param.top_p"); !ok || v != "0.9 @ config/generation.yaml:5" {
		t.Errorf("ai-config airom:param.top_p = %q,%v", v, ok)
	}
}

func TestVersion17(t *testing.T) {
	raw := encode(t, writer.Options{CDXVersion: "1.7"})
	var bom cyclonedx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if bom.SpecVersion != cyclonedx.SpecVersion1_7 {
		t.Errorf("specVersion = %v, want 1.7", bom.SpecVersion)
	}
	if !bytes.Contains(raw, []byte("bom-1.7.schema.json")) {
		t.Error("1.7 output should reference the 1.7 schema")
	}
}

// TestCDXScoringMethod pins the vector→method mapping: labeling a v2/v4 vector
// as CVSSv31 would misdirect any consumer that parses the score per the method.
func TestCDXScoringMethod(t *testing.T) {
	cases := []struct {
		vector string
		want   cyclonedx.ScoringMethod
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cyclonedx.ScoringMethodCVSSv31},
		{"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", cyclonedx.ScoringMethodCVSSv3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", cyclonedx.ScoringMethodCVSSv4},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", cyclonedx.ScoringMethodCVSSv2}, // bare v2, no prefix
		{"something-else", cyclonedx.ScoringMethodOther},
	}
	for _, c := range cases {
		if got := cdxScoringMethod(c.vector); got != c.want {
			t.Errorf("cdxScoringMethod(%q) = %q, want %q", c.vector, got, c.want)
		}
	}
}

// TestEOLProjectsAsPropertiesNotVulnerabilities pins the placement decision: a
// scheduled vendor retirement is an availability fact, not a defect. Filing it
// in vulnerabilities[] would put a non-CVE with no CVSS into the array that
// downstream triage and VEX tooling treat as security findings.
func TestEOLProjectsAsPropertiesNotVulnerabilities(t *testing.T) {
	var bom cyclonedx.BOM
	if err := json.Unmarshal(encode(t, writer.Options{}), &bom); err != nil {
		t.Fatal(err)
	}
	var props map[string]string
	for _, c := range *bom.Components {
		if c.BOMRef != string(idHosted) {
			continue
		}
		props = map[string]string{}
		for _, p := range *c.Properties {
			props[p.Name] = p.Value
		}
	}
	if props == nil {
		t.Fatal("hosted component not found")
	}
	want := map[string]string{
		"airom:eol.state":            "deprecated",
		"airom:eol.shutdownDate":     "2026-10-23",
		"airom:eol.announcedDate":    "2026-04-22",
		"airom:eol.daysRemaining":    "99",
		"airom:eol.replacement":      "gpt-4.2",
		"airom:eol.replacementState": "retired", // the target is itself dead
		"airom:eol.source":           "airom-catalog",
		"airom:eol.verified":         "2026-07-16",
	}
	for k, v := range want {
		if props[k] != v {
			t.Errorf("%s = %q, want %q", k, props[k], v)
		}
	}
	// Dates are calendar days, never timestamps: a consumer west of UTC must
	// not read 2026-10-23 as the 22nd.
	for _, k := range []string{"airom:eol.shutdownDate", "airom:eol.announcedDate", "airom:eol.verified"} {
		if strings.Contains(props[k], "T") {
			t.Errorf("%s = %q, want a bare YYYY-MM-DD day", k, props[k])
		}
	}
	// And nothing lifecycle-shaped leaked into vulnerabilities[].
	if bom.Vulnerabilities != nil {
		for _, v := range *bom.Vulnerabilities {
			if strings.Contains(strings.ToLower(v.ID), "eol") {
				t.Errorf("EOL must not appear in vulnerabilities[], found %q", v.ID)
			}
		}
	}
}

func TestDeterministic(t *testing.T) {
	a := encode(t, writer.Options{})
	b := encode(t, writer.Options{})
	if !bytes.Equal(a, b) {
		t.Error("two encodes of identical input differ (P7 violated)")
	}
}

func TestGolden(t *testing.T) {
	raw := encode(t, writer.Options{})
	golden := filepath.Join("testdata", "inventory.golden.cdx.json")

	if *update || os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated golden %s", golden)
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(raw, want) {
		t.Errorf("output differs from golden; run: go test ./internal/writer/cdx/... -update")
	}
}

// ── test helpers ────────────────────────────────────────────────────────────

func derefComponents(c *[]cyclonedx.Component) []cyclonedx.Component {
	if c == nil {
		return nil
	}
	return *c
}

func findComp(comps []cyclonedx.Component, ref string) *cyclonedx.Component {
	for i := range comps {
		if comps[i].BOMRef == ref {
			return &comps[i]
		}
	}
	return nil
}

func propVal(props *[]cyclonedx.Property, name string) (string, bool) {
	if props == nil {
		return "", false
	}
	for _, p := range *props {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

func hasExtRef(refs *[]cyclonedx.ExternalReference, typ cyclonedx.ExternalReferenceType) bool {
	if refs == nil {
		return false
	}
	for _, r := range *refs {
		if r.Type == typ {
			return true
		}
	}
	return false
}
