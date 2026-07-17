package assemble

import (
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

func opts() Options {
	return Options{
		Tool:      airom.ToolInfo{Name: "airom", Version: "test"},
		Source:    airom.SourceInfo{Kind: "dir", Target: "/src/app"},
		Lifecycle: "pre-build",
		Serial:    "urn:uuid:00000000-0000-4000-8000-000000000000",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func finding(kind airom.ComponentKind, name, provider, detector string, method airom.DetectionMethod, conf float64, path string, line int) detect.Finding {
	return detect.Finding{
		Claim: detect.ComponentClaim{Kind: kind, Name: name, Provider: provider},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Path: path, Line: line},
			DetectorID: detector,
			Method:     method,
			Confidence: airom.Confidence(conf),
		},
	}
}

func componentByName(t *testing.T, inv *airom.Inventory, name string) airom.Component {
	t.Helper()
	for _, c := range inv.Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no component named %q in %+v", name, inv.Components)
	return airom.Component{}
}

// TestClassCollision: an embeddings rule and a generic provider rule seeing
// the same model must collide into ONE component with the more specific
// kind (§9.1, the Class ≠ Kind design).
func TestClassCollision(t *testing.T) {
	inv := Build([]detect.Finding{
		finding(airom.KindHostedLLM, "text-embedding-3-large", "openai", "rules/openai/model-literal", airom.MethodSourceCode, 0.85, "a.py", 10),
		finding(airom.KindEmbeddingModel, "text-embedding-3-large", "openai", "rules/openai-embed/embedding-literal", airom.MethodSourceCode, 0.9, "b.py", 20),
	}, nil, airom.ScanStats{}, opts())

	c := componentByName(t, inv, "text-embedding-3-large")
	if c.Kind != airom.KindEmbeddingModel {
		t.Errorf("kind = %s, want embedding-model (facet precedence)", c.Kind)
	}
	if n := len(c.Evidence.Occurrences); n != 2 {
		t.Errorf("occurrences = %d, want 2 (one component, both sightings)", n)
	}
	// hosted models get NO purl (D9) but do get airom:model.* props
	if c.PURL != "" {
		t.Errorf("purl = %q, want empty for hosted model", c.PURL)
	}
	var hasProvider bool
	for _, p := range c.Props {
		if p.Name == "airom:model.provider" && p.Value == "openai" {
			hasProvider = true
		}
	}
	if !hasProvider {
		t.Errorf("missing airom:model.provider prop: %+v", c.Props)
	}
}

// TestWeightsIdentityIsContentHash: same hash at two paths = ONE component;
// different hashes sharing a basename = TWO (§9.1).
func TestWeightsIdentityIsContentHash(t *testing.T) {
	h1 := airom.Hash{Alg: "SHA-256", Hex: strings.Repeat("aa", 32)}
	h2 := airom.Hash{Alg: "SHA-256", Hex: strings.Repeat("bb", 32)}
	mk := func(path string, h airom.Hash) detect.Finding {
		f := finding(airom.KindLocalModelFile, "llama.gguf", "local", "modelfile/gguf", airom.MethodBinary, 0.95, path, 0)
		f.Claim.Hashes = []airom.Hash{h}
		return f
	}

	inv := Build([]detect.Finding{
		mk("models/llama.gguf", h1),
		mk("backup/llama.gguf", h1),
		mk("other/llama.gguf", h2),
	}, nil, airom.ScanStats{}, opts())

	var weights []airom.Component
	for _, c := range inv.Components {
		if c.Kind == airom.KindLocalModelFile {
			weights = append(weights, c)
		}
	}
	if len(weights) != 2 {
		t.Fatalf("weights components = %d, want 2 (same bytes merge, different bytes never)", len(weights))
	}
	for _, c := range weights {
		if sha256Of(c.Hashes) == strings.Repeat("aa", 32) {
			if n := len(c.Evidence.Occurrences); n != 2 {
				t.Errorf("h1 component occurrences = %d, want 2", n)
			}
			wantPURL := "pkg:generic/llama.gguf?checksum=sha256:" + strings.Repeat("aa", 32)
			if c.PURL != wantPURL {
				t.Errorf("purl = %q, want %q", c.PURL, wantPURL)
			}
		}
	}
}

// TestConfidenceWorkedExamples pins the §9.3 arithmetic exactly.
func TestConfidenceWorkedExamples(t *testing.T) {
	// gpt-4.1 from one 0.85 rule in 12 files → 0.85 + 0.15·min(0.05·11, 0.15) ≈ 0.8725
	var fs []detect.Finding
	for i := 0; i < 12; i++ {
		fs = append(fs, finding(airom.KindHostedLLM, "gpt-4.1", "openai", "rules/openai/model-literal", airom.MethodSourceCode, 0.85, "f.py", 10+i))
	}
	inv := Build(fs, nil, airom.ScanStats{}, opts())
	c := componentByName(t, inv, "gpt-4.1")
	if got, want := float64(c.Confidence), 0.85+(1-0.85)*0.15; math.Abs(got-want) > 1e-9 {
		t.Errorf("repetition confidence = %v, want %v (twelve sightings must not launder into certainty)", got, want)
	}

	// filename 0.5 + binary-analysis 0.95 → 1 − 0.5·0.05 = 0.975
	inv = Build([]detect.Finding{
		finding(airom.KindHostedLLM, "m", "p", "det-a", airom.MethodFilename, 0.5, "a", 1),
		finding(airom.KindHostedLLM, "m", "p", "det-b", airom.MethodBinary, 0.95, "b", 1),
	}, nil, airom.ScanStats{}, opts())
	c = componentByName(t, inv, "m")
	if got := float64(c.Confidence); math.Abs(got-0.975) > 1e-9 {
		t.Errorf("cross-method confidence = %v, want 0.975", got)
	}

	// clamp: many strong non-hash methods cap at 0.99
	inv = Build([]detect.Finding{
		finding(airom.KindHostedLLM, "x", "p", "d1", airom.MethodSourceCode, 0.98, "a", 1),
		finding(airom.KindHostedLLM, "x", "p", "d2", airom.MethodManifest, 0.98, "b", 1),
		finding(airom.KindHostedLLM, "x", "p", "d3", airom.MethodBinary, 0.98, "c", 1),
	}, nil, airom.ScanStats{}, opts())
	c = componentByName(t, inv, "x")
	if got := float64(c.Confidence); got != 0.99 {
		t.Errorf("clamped confidence = %v, want 0.99 (1.0 is reserved for hash/attestation)", got)
	}

	// hash evidence may exceed the clamp
	inv = Build([]detect.Finding{
		finding(airom.KindLocalModelFile, "w.gguf", "local", "d1", airom.MethodHash, 1.0, "a", 0),
	}, nil, airom.ScanStats{}, opts())
	c = componentByName(t, inv, "w.gguf")
	if got := float64(c.Confidence); got != 1.0 {
		t.Errorf("hash confidence = %v, want 1.0", got)
	}
}

// TestDateSuffixFolding: gpt-4.1-2026-01-14 folds into gpt-4.1 with a
// version claim (§9.1) — never a twin component.
func TestDateSuffixFolding(t *testing.T) {
	inv := Build([]detect.Finding{
		finding(airom.KindHostedLLM, "gpt-4.1", "openai", "d1", airom.MethodSourceCode, 0.85, "a.py", 1),
		finding(airom.KindHostedLLM, "gpt-4.1-2026-01-14", "openai", "d2", airom.MethodConfig, 0.7, "cfg.yaml", 2),
	}, nil, airom.ScanStats{}, opts())

	c := componentByName(t, inv, "gpt-4.1")
	models := 0
	for _, comp := range inv.Components {
		if comp.Kind == airom.KindHostedLLM {
			models++
		}
	}
	if models != 1 {
		t.Fatalf("hosted models = %d, want 1 (date suffix folds)", models)
	}
	if v, ok := c.Version.Value(); !ok || v != "2026-01-14" {
		t.Errorf("version = %v %v, want 2026-01-14 from the folded suffix", v, ok)
	}
}

// TestVersionConflictKeepsClaims: competing versions keep the winner in
// Version and every claim in evidence.identity (§9.2).
func TestVersionConflictKeepsClaims(t *testing.T) {
	f1 := finding(airom.KindFramework, "langchain", "", "manifest/pypi", airom.MethodManifest, 0.95, "requirements.txt", 3)
	f1.Claim.Version = "0.2.1"
	f1.Claim.Package = &detect.PackageClaim{Ecosystem: "pypi"}
	f2 := finding(airom.KindFramework, "langchain", "", "rules/langchain/import", airom.MethodSourceCode, 0.6, "app.py", 1)
	f2.Claim.Version = "0.1.0"
	f2.Claim.Package = &detect.PackageClaim{Ecosystem: "pypi"}

	inv := Build([]detect.Finding{f1, f2}, nil, airom.ScanStats{}, opts())
	c := componentByName(t, inv, "langchain")
	if v, _ := c.Version.Value(); v != "0.2.1" {
		t.Errorf("version = %q, want manifest-confidence winner 0.2.1", v)
	}
	if len(c.Evidence.Identity) < 2 {
		t.Errorf("identity claims = %d, want both competing versions preserved", len(c.Evidence.Identity))
	}
	if c.PURL != "pkg:pypi/langchain@0.2.1" {
		t.Errorf("purl = %q", c.PURL)
	}
}

// TestRelationResolution: from_field edges resolve against assembled
// components; unresolvable hints warn, never fabricate (§6.1).
func TestRelationResolution(t *testing.T) {
	model := finding(airom.KindHostedLLM, "gpt-4.1", "openai", "rules/openai/model-literal", airom.MethodSourceCode, 0.85, "app.py", 10)
	sdk := finding(airom.KindLibrary, "openai-sdk", "openai", "rules/openai/chat-call", airom.MethodSourceCode, 0.7, "app.py", 12)
	sdk.Occurrence.Fields = map[string]string{"model": "gpt-4.1"}
	sdk.Relations = []detect.RelationClaim{
		{Type: airom.RelUses, Target: detect.TargetHint{Kind: airom.KindHostedLLM, FromField: "model"}},
		{Type: airom.RelQueries, Target: detect.TargetHint{Kind: airom.KindVectorDB, Name: "no-such-db"}},
	}

	inv := Build([]detect.Finding{model, sdk}, nil, airom.ScanStats{}, opts())

	if len(inv.Relationships) != 1 {
		t.Fatalf("relationships = %d, want exactly 1 (unresolved hint must not fabricate)", len(inv.Relationships))
	}
	rel := inv.Relationships[0]
	if rel.Type != airom.RelUses {
		t.Errorf("rel type = %s", rel.Type)
	}
	from := componentByName(t, inv, "openai") // "openai-sdk" claim canonicalizes to the package name
	to := componentByName(t, inv, "gpt-4.1")
	if rel.From != from.ID || rel.To != to.ID {
		t.Errorf("edge %s→%s, want sdk→model", rel.From, rel.To)
	}
	if len(rel.Evidence) == 0 {
		t.Error("edge has no call-site evidence")
	}
	warned := false
	for _, w := range inv.Stats.Warnings {
		if strings.Contains(w, "no-such-db") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("missing dangling-hint warning: %v", inv.Stats.Warnings)
	}
}

// TestParamPromotion: call-site captured params bind to the model the SAME
// occurrence names — with provenance, no averaging (§9.5).
func TestParamPromotion(t *testing.T) {
	model := finding(airom.KindHostedLLM, "gpt-4.1", "openai", "rules/openai/model-literal", airom.MethodSourceCode, 0.85, "app.py", 10)
	call := finding(airom.KindLibrary, "openai-sdk", "openai", "rules/openai/chat-call", airom.MethodSourceCode, 0.7, "app.py", 12)
	call.Occurrence.Fields = map[string]string{"model": "gpt-4.1", "param.temperature": "0.2"}
	call2 := finding(airom.KindLibrary, "openai-sdk", "openai", "rules/openai/chat-call", airom.MethodSourceCode, 0.7, "batch.py", 30)
	call2.Occurrence.Fields = map[string]string{"model": "gpt-4.1", "param.temperature": "0.9"}

	inv := Build([]detect.Finding{model, call, call2}, nil, airom.ScanStats{}, opts())
	c := componentByName(t, inv, "gpt-4.1")
	if c.Model == nil {
		t.Fatal("no model facet")
	}
	if len(c.Model.GenerationParams) != 2 {
		t.Fatalf("params = %d, want 2 (two call sites stay two BoundParams)", len(c.Model.GenerationParams))
	}
	for _, p := range c.Model.GenerationParams {
		if p.Name != "temperature" || p.Occurrence == nil {
			t.Errorf("param %+v lacks name/provenance", p)
		}
	}
}

// TestOrderIndependence: shuffled findings assemble to a deeply equal
// inventory (P7 property).
func TestOrderIndependence(t *testing.T) {
	base := []detect.Finding{
		finding(airom.KindHostedLLM, "gpt-4.1", "openai", "d1", airom.MethodSourceCode, 0.85, "a.py", 1),
		finding(airom.KindHostedLLM, "gpt-4.1", "openai", "d2", airom.MethodManifest, 0.7, "req.txt", 2),
		finding(airom.KindVectorDB, "chroma", "", "d3", airom.MethodSourceCode, 0.8, "db.py", 3),
		finding(airom.KindEmbeddingModel, "text-embedding-3-large", "openai", "d4", airom.MethodSourceCode, 0.9, "e.py", 4),
		finding(airom.KindFramework, "langchain", "", "d5", airom.MethodManifest, 0.95, "req.txt", 5),
	}
	want := Build(base, nil, airom.ScanStats{}, opts())

	rng := rand.New(rand.NewSource(42))
	for trial := 0; trial < 20; trial++ {
		shuffled := append([]detect.Finding(nil), base...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got := Build(shuffled, nil, airom.ScanStats{}, opts())
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("trial %d: shuffled findings produced a different inventory", trial)
		}
	}
}

// TestConfidenceMonotonic: adding evidence never decreases confidence.
func TestConfidenceMonotonic(t *testing.T) {
	fs := []detect.Finding{
		finding(airom.KindHostedLLM, "m", "p", "d1", airom.MethodSourceCode, 0.5, "a", 1),
	}
	prev := 0.0
	methods := []airom.DetectionMethod{airom.MethodManifest, airom.MethodBinary, airom.MethodConfig, airom.MethodFilename}
	for i, m := range methods {
		fs = append(fs, finding(airom.KindHostedLLM, "m", "p", "d"+string(rune('2'+i)), m, 0.4, "f", i))
		inv := Build(fs, nil, airom.ScanStats{}, opts())
		c := componentByName(t, inv, "m")
		if float64(c.Confidence) < prev {
			t.Fatalf("confidence decreased: %v < %v after adding %s", c.Confidence, prev, m)
		}
		prev = float64(c.Confidence)
	}
}

// TestFacetConflictDemotes: two different Known values demote to Unknown
// with a warning — never a silent pick (§9.2).
func TestFacetConflictDemotes(t *testing.T) {
	h := airom.Hash{Alg: "SHA-256", Hex: strings.Repeat("cc", 32)}
	f1 := finding(airom.KindLocalModelFile, "m.gguf", "local", "d1", airom.MethodBinary, 0.9, "m.gguf", 0)
	f1.Claim.Hashes = []airom.Hash{h}
	f1.Claim.Model = &detect.ModelClaim{ParamCount: 7_000_000_000}
	f2 := finding(airom.KindLocalModelFile, "m.gguf", "local", "d2", airom.MethodBinary, 0.9, "m.gguf", 0)
	f2.Claim.Hashes = []airom.Hash{h}
	f2.Claim.Model = &detect.ModelClaim{ParamCount: 8_000_000_000}

	inv := Build([]detect.Finding{f1, f2}, nil, airom.ScanStats{}, opts())
	c := componentByName(t, inv, "m.gguf")
	if c.Model == nil {
		t.Fatal("no facet")
	}
	if !c.Model.ParamCount.IsZero() {
		if _, known := c.Model.ParamCount.Value(); known {
			t.Error("conflicting ParamCount stayed Known; want demoted to Unknown")
		}
	}
	if len(inv.Stats.Warnings) == 0 {
		t.Error("conflict produced no warning")
	}
}

// TestRootMinted: the application root exists and is deterministic.
func TestRootMinted(t *testing.T) {
	inv := Build(nil, nil, airom.ScanStats{}, opts())
	if inv.Root == "" {
		t.Fatal("no root")
	}
	found := false
	for _, c := range inv.Components {
		if c.ID == inv.Root && c.Kind == airom.KindApplication && c.Name == "app" {
			found = true
		}
	}
	if !found {
		t.Errorf("root component missing/misnamed: %+v", inv.Components)
	}
}

// TestConfidenceBitDeterminism: float multiplication order is pinned, so a
// multi-method component's confidence is bit-identical across many builds
// (P7 regression: map-iteration order previously leaked into rounding).
func TestConfidenceBitDeterminism(t *testing.T) {
	fs := []detect.Finding{
		finding(airom.KindHostedLLM, "m", "p", "d1", airom.MethodFilename, 0.23, "a", 1),
		finding(airom.KindHostedLLM, "m", "p", "d2", airom.MethodBinary, 0.17, "b", 1),
		finding(airom.KindHostedLLM, "m", "p", "d3", airom.MethodSourceCode, 0.31, "c", 1),
		finding(airom.KindHostedLLM, "m", "p", "d4", airom.MethodManifest, 0.41, "d", 1),
	}
	first := componentByName(t, Build(fs, nil, airom.ScanStats{}, opts()), "m").Confidence
	for i := 0; i < 2000; i++ {
		got := componentByName(t, Build(fs, nil, airom.ScanStats{}, opts()), "m").Confidence
		if got != first {
			t.Fatalf("iteration %d: confidence %v != %v (bit-level nondeterminism)", i, got, first)
		}
	}
}

// TestPromoteParamsOrderDeterminism: params differing only by column keep a
// stable order across builds (P7 regression).
func TestPromoteParamsOrderDeterminism(t *testing.T) {
	model := finding(airom.KindHostedLLM, "gpt-4.1", "openai", "rules/a/model", airom.MethodSourceCode, 0.85, "app.py", 1)
	mk := func(det string, col int) detect.Finding {
		f := finding(airom.KindLibrary, "sdk-"+det, "openai", det, airom.MethodSourceCode, 0.7, "app.py", 5)
		f.Occurrence.Location.Column = col
		f.Occurrence.Fields = map[string]string{"model": "gpt-4.1", "param.temperature": "0.2"}
		return f
	}
	fs := []detect.Finding{model, mk("rules/a/call", 1), mk("rules/b/call", 30)}

	want := componentByName(t, Build(fs, nil, airom.ScanStats{}, opts()), "gpt-4.1").Model.GenerationParams
	for i := 0; i < 200; i++ {
		got := componentByName(t, Build(fs, nil, airom.ScanStats{}, opts()), "gpt-4.1").Model.GenerationParams
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("iteration %d: GenerationParams order changed", i)
		}
	}
}

// TestFromFieldResolvesCaptureParamName: rule-schema.md target-hint form 2
// with a capture_params name (stored as "param.<name>") must resolve.
func TestFromFieldResolvesCaptureParamName(t *testing.T) {
	svc := finding(airom.KindService, "prod-gpt4", "azure", "rules/az/deployment", airom.MethodConfig, 0.8, "deploy.yaml", 2)
	caller := finding(airom.KindLibrary, "az-sdk", "azure", "rules/az/call", airom.MethodSourceCode, 0.7, "app.py", 9)
	caller.Occurrence.Fields = map[string]string{"param.deployment": "prod-gpt4"}
	caller.Relations = []detect.RelationClaim{
		{Type: airom.RelUses, Target: detect.TargetHint{Kind: airom.KindService, FromField: "deployment"}},
	}
	inv := Build([]detect.Finding{svc, caller}, nil, airom.ScanStats{}, opts())
	if len(inv.Relationships) != 1 {
		t.Fatalf("relationships = %d, want the capture_params-named edge to resolve (warnings: %v)",
			len(inv.Relationships), inv.Stats.Warnings)
	}
}

// TestLocalRefAmbiguityRefused: multiple distinct same-file claims by the
// referenced rule refuse resolution — never a guessed edge.
func TestLocalRefAmbiguityRefused(t *testing.T) {
	m1 := finding(airom.KindHostedLLM, "gpt-4.1", "openai", "rules/openai/model-literal", airom.MethodSourceCode, 0.85, "app.py", 3)
	m2 := finding(airom.KindHostedLLM, "o3", "openai", "rules/openai/model-literal", airom.MethodSourceCode, 0.85, "app.py", 9)
	x := finding(airom.KindLibrary, "sdk", "openai", "rules/openai/import", airom.MethodSourceCode, 0.6, "app.py", 1)
	x.Relations = []detect.RelationClaim{
		{Type: airom.RelUses, Target: detect.TargetHint{LocalRef: "openai/model-literal"}},
	}
	inv := Build([]detect.Finding{m1, m2, x}, nil, airom.ScanStats{}, opts())
	if len(inv.Relationships) != 0 {
		t.Fatalf("relationships = %+v, want none (ambiguous local_ref must refuse)", inv.Relationships)
	}
	found := false
	for _, w := range inv.Stats.Warnings {
		if strings.Contains(w, "ambiguous local_ref") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing ambiguity warning: %v", inv.Stats.Warnings)
	}

	// The unambiguous case still resolves.
	inv = Build([]detect.Finding{m1, x}, nil, airom.ScanStats{}, opts())
	if len(inv.Relationships) != 1 {
		t.Fatalf("unambiguous local_ref failed to resolve: %v", inv.Stats.Warnings)
	}
}

// TestPackageFoldAndAlias: a manifest-declared package and a usage-detected
// one (client-package alias) merge into one component (§9.1).
func TestPackageFoldAndAlias(t *testing.T) {
	// langchain declared in a manifest (pypi) + detected in usage (no ecosystem).
	manifest := finding(airom.KindFramework, "langchain", "", "manifest/pypi", airom.MethodManifest, 0.95, "requirements.txt", 1)
	manifest.Claim.Version = "0.2.1"
	manifest.Claim.Package = &detect.PackageClaim{Ecosystem: "pypi"}
	usage := finding(airom.KindFramework, "langchain", "", "rules/langchain/import", airom.MethodSourceCode, 0.7, "app.py", 3)

	// chromadb (manifest, vector-db) + chroma (usage rule) via alias.
	cdbManifest := finding(airom.KindVectorDB, "chromadb", "", "manifest/pypi", airom.MethodManifest, 0.95, "requirements.txt", 2)
	cdbManifest.Claim.Package = &detect.PackageClaim{Ecosystem: "pypi"}
	chromaUsage := finding(airom.KindVectorDB, "chroma", "", "rules/chroma/client", airom.MethodSourceCode, 0.7, "app.py", 5)

	inv := Build([]detect.Finding{manifest, usage, cdbManifest, chromaUsage}, nil, airom.ScanStats{}, opts())

	frameworks, vecdbs := 0, 0
	for _, c := range inv.Components {
		switch c.Kind {
		case airom.KindFramework:
			frameworks++
			if len(c.Evidence.Occurrences) != 2 {
				t.Errorf("langchain occurrences = %d, want 2 (manifest + usage folded)", len(c.Evidence.Occurrences))
			}
			if v, _ := c.Version.Value(); v != "0.2.1" {
				t.Errorf("langchain version = %q, want 0.2.1 from the manifest", v)
			}
		case airom.KindVectorDB:
			vecdbs++
			if c.Name != "chroma" {
				t.Errorf("vector-db name = %q, want chroma (alias)", c.Name)
			}
			if len(c.Evidence.Occurrences) != 2 {
				t.Errorf("chroma occurrences = %d, want 2 (chromadb + chroma merged)", len(c.Evidence.Occurrences))
			}
		}
	}
	if frameworks != 1 {
		t.Errorf("framework components = %d, want 1 (folded)", frameworks)
	}
	if vecdbs != 1 {
		t.Errorf("vector-db components = %d, want 1 (aliased)", vecdbs)
	}
}

// TestSDKUsageFoldsIntoManifestPackage: the Cisco-comparison double-count.
// A vendor package declared in a manifest and its SDK usage detected in code
// ("openai" + "openai-sdk", "anthropic" + "@anthropic-ai/sdk") are ONE
// library; provider spelling variants ("Hugging Face" vs "huggingface") and
// kind variants (framework vs library) must not split transformers.
func TestSDKUsageFoldsIntoManifestPackage(t *testing.T) {
	oaiManifest := finding(airom.KindLibrary, "openai", "OpenAI", "manifest/pypi", airom.MethodManifest, 0.95, "requirements.txt", 1)
	oaiManifest.Claim.Version = "1.51.0"
	oaiManifest.Claim.Package = &detect.PackageClaim{Ecosystem: "pypi"}
	oaiUsage := finding(airom.KindLibrary, "openai-sdk", "openai", "rules/openai/chat-call", airom.MethodSourceCode, 0.7, "app.py", 12)

	antManifest := finding(airom.KindLibrary, "@anthropic-ai/sdk", "Anthropic", "manifest/npm", airom.MethodManifest, 0.95, "package.json", 4)
	antManifest.Claim.Version = "0.27.3"
	antManifest.Claim.Package = &detect.PackageClaim{Ecosystem: "npm"}
	antUsage := finding(airom.KindLibrary, "anthropic-sdk", "anthropic", "rules/anthropic/messages-call", airom.MethodSourceCode, 0.7, "app.js", 8)

	tfManifest := finding(airom.KindFramework, "transformers", "Hugging Face", "manifest/pypi", airom.MethodManifest, 0.95, "requirements.txt", 3)
	tfManifest.Claim.Version = "4.44.0"
	tfManifest.Claim.Package = &detect.PackageClaim{Ecosystem: "pypi"}
	tfUsage := finding(airom.KindLibrary, "transformers", "huggingface", "rules/transformers/import", airom.MethodSourceCode, 0.7, "train.py", 2)

	inv := Build([]detect.Finding{oaiManifest, oaiUsage, antManifest, antUsage, tfManifest, tfUsage}, nil, airom.ScanStats{}, opts())

	pkgs := 0
	var got []string
	for _, c := range inv.Components {
		if c.Kind == airom.KindLibrary || c.Kind == airom.KindFramework {
			pkgs++
			got = append(got, string(c.Kind)+":"+c.Name)
		}
	}
	if pkgs != 3 {
		t.Fatalf("package components = %d, want 3 (each manifest+usage pair folds): %v", pkgs, got)
	}
	oai := componentByName(t, inv, "openai")
	if len(oai.Evidence.Occurrences) != 2 {
		t.Errorf("openai occurrences = %d, want 2", len(oai.Evidence.Occurrences))
	}
	if v, _ := oai.Version.Value(); v != "1.51.0" {
		t.Errorf("openai version = %q, want 1.51.0 from the manifest", v)
	}
	if oai.PURL != "pkg:pypi/openai@1.51.0" {
		t.Errorf("openai purl = %q, want pkg:pypi/openai@1.51.0", oai.PURL)
	}
	ant := componentByName(t, inv, "anthropic")
	if len(ant.Evidence.Occurrences) != 2 {
		t.Errorf("anthropic occurrences = %d, want 2", len(ant.Evidence.Occurrences))
	}
	// The purl must name the DECLARED npm distribution — pkg:npm/anthropic
	// does not exist (adversarial review finding).
	if ant.PURL != "pkg:npm/%40anthropic-ai/sdk@0.27.3" {
		t.Errorf("anthropic purl = %q, want pkg:npm/%%40anthropic-ai/sdk@0.27.3 (declared distribution)", ant.PURL)
	}
	tf := componentByName(t, inv, "transformers")
	if tf.Kind != airom.KindFramework {
		t.Errorf("transformers kind = %s, want framework (precedence over library)", tf.Kind)
	}
	if len(tf.Evidence.Occurrences) != 2 {
		t.Errorf("transformers occurrences = %d, want 2", len(tf.Evidence.Occurrences))
	}
}

// TestFoldedUsageKeepsEdgeEndpoints: a uses edge claimed by a usage finding
// whose draft folds into the manifest component must depart from the SURVIVOR,
// not from the fold-deleted draft's ID. (Adversarial review HIGH: both e2e
// goldens carried a dangling From, and the CDX writer silently dropped the
// edge — the exact edge the dedup work exists to keep.)
func TestFoldedUsageKeepsEdgeEndpoints(t *testing.T) {
	model := finding(airom.KindHostedLLM, "gpt-4.1", "openai", "rules/openai/model-literal", airom.MethodSourceCode, 0.85, "app.py", 10)
	manifest := finding(airom.KindLibrary, "openai", "OpenAI", "manifest/pypi", airom.MethodManifest, 0.95, "requirements.txt", 1)
	manifest.Claim.Version = "1.51.0"
	manifest.Claim.Package = &detect.PackageClaim{Ecosystem: "pypi"}
	usage := finding(airom.KindLibrary, "openai", "openai", "rules/openai/chat-call", airom.MethodSourceCode, 0.7, "app.py", 12)
	usage.Occurrence.Fields = map[string]string{"model": "gpt-4.1"}
	usage.Relations = []detect.RelationClaim{
		{Type: airom.RelUses, Target: detect.TargetHint{Kind: airom.KindHostedLLM, FromField: "model"}},
	}

	inv := Build([]detect.Finding{model, manifest, usage}, nil, airom.ScanStats{}, opts())

	if len(inv.Relationships) != 1 {
		t.Fatalf("relationships = %d, want 1", len(inv.Relationships))
	}
	rel := inv.Relationships[0]
	byID := map[airom.ID]airom.Component{}
	for _, c := range inv.Components {
		byID[c.ID] = c
	}
	from, ok := byID[rel.From]
	if !ok {
		t.Fatalf("edge From %s is not any component ID (dangling after fold)", rel.From)
	}
	if from.Name != "openai" || len(from.Evidence.Occurrences) != 2 {
		t.Errorf("edge departs from %q with %d occurrences, want the folded openai with 2", from.Name, len(from.Evidence.Occurrences))
	}
	if to, ok := byID[rel.To]; !ok || to.Name != "gpt-4.1" {
		t.Errorf("edge To = %v (ok=%v), want the gpt-4.1 component", rel.To, ok)
	}
}

// TestPackageFoldRefusesAmbiguity: same name in two ecosystems stays split.
func TestPackageFoldRefusesAmbiguity(t *testing.T) {
	py := finding(airom.KindLibrary, "redis", "", "manifest/pypi", airom.MethodManifest, 0.95, "requirements.txt", 1)
	py.Claim.Package = &detect.PackageClaim{Ecosystem: "pypi"}
	npm := finding(airom.KindLibrary, "redis", "", "manifest/npm", airom.MethodManifest, 0.95, "package.json", 1)
	npm.Claim.Package = &detect.PackageClaim{Ecosystem: "npm"}
	usage := finding(airom.KindLibrary, "redis", "", "rules/redis/import", airom.MethodSourceCode, 0.7, "app.py", 1)

	inv := Build([]detect.Finding{py, npm, usage}, nil, airom.ScanStats{}, opts())
	libs := 0
	for _, c := range inv.Components {
		if c.Kind == airom.KindLibrary {
			libs++
		}
	}
	// pypi and npm stay distinct; the disc-less usage cannot pick a unique
	// home, so it stays separate too (refusal over guessing).
	if libs != 3 {
		t.Errorf("library components = %d, want 3 (ambiguous ecosystem: no fold)", libs)
	}
}
