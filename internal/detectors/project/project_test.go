package project

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"sort"
	"testing"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// fakeResolver serves an in-memory path→bytes map, matching FilesByGlob
// through the SDK's own detect.Match so routing mirrors the engine's.
type fakeResolver struct {
	files map[string]string
}

func (fr *fakeResolver) FilesByGlob(_ context.Context, patterns ...string) ([]detect.FileRef, error) {
	paths := make([]string, 0, len(fr.files))
	for p := range fr.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var out []detect.FileRef
	for _, p := range paths {
		for _, pat := range patterns {
			if detect.Match(pat, p) {
				out = append(out, fr.ref(p))
				break
			}
		}
	}
	return out, nil
}

func (fr *fakeResolver) Open(p string) (io.ReadCloser, error) {
	b, ok := fr.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader([]byte(b))), nil
}

func (fr *fakeResolver) Stat(p string) (detect.FileRef, error) {
	if _, ok := fr.files[p]; !ok {
		return detect.FileRef{}, fs.ErrNotExist
	}
	return fr.ref(p), nil
}

func (fr *fakeResolver) ref(p string) detect.FileRef {
	return detect.FileRef{Path: p, Size: int64(len(fr.files[p])), Language: detect.LanguageOf(p)}
}

func run(t *testing.T, d detect.ProjectDetector, files map[string]string, prior *detect.FindingsView) []detect.Finding {
	t.Helper()
	got, err := d.DetectProject(context.Background(), &fakeResolver{files: files}, prior)
	if err != nil {
		t.Fatalf("DetectProject error: %v", err)
	}
	return got
}

// tinyWeights is a handcrafted non-empty stand-in for a weights file — never a
// real checkpoint.
const tinyWeights = "\x00\x01\x02\x03weights"

// ── HFDir ──────────────────────────────────────────────────────────────────

func TestHFDir_TransformersDir(t *testing.T) {
	files := map[string]string{
		"models/llama/config.json":       `{"model_type":"llama","_name_or_path":"llama-2-7b"}`,
		"models/llama/model.safetensors": tinyWeights,
		"models/llama/tokenizer.json":    `{}`,
	}
	got := run(t, NewHFDir(), files, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Claim.Kind != airom.KindLocalModelFile {
		t.Errorf("kind = %q, want %q", f.Claim.Kind, airom.KindLocalModelFile)
	}
	if f.Claim.Name != "llama-2-7b" {
		t.Errorf("name = %q, want _name_or_path llama-2-7b", f.Claim.Name)
	}
	if f.Claim.Provider != "local" {
		t.Errorf("provider = %q, want local", f.Claim.Provider)
	}
	if f.Claim.Model == nil || f.Claim.Model.Architecture != "llama" {
		t.Errorf("architecture = %+v, want llama", f.Claim.Model)
	}
	if f.Claim.Model.Format != "safetensors" {
		t.Errorf("format = %q, want safetensors", f.Claim.Model.Format)
	}
	if f.Occurrence.Location.Path != "models/llama/config.json" || f.Occurrence.Location.Line != 0 {
		t.Errorf("occurrence = %+v, want config.json line 0", f.Occurrence.Location)
	}
	if f.Occurrence.Method != airom.MethodBinary {
		t.Errorf("method = %q, want binary", f.Occurrence.Method)
	}
	if f.Occurrence.Confidence != 0.9 {
		t.Errorf("confidence = %v, want 0.9", f.Occurrence.Confidence)
	}
	if f.Occurrence.DetectorID != "project/hfdir" {
		t.Errorf("detectorID = %q", f.Occurrence.DetectorID)
	}
}

func TestHFDir_ArchitecturesOnlyName(t *testing.T) {
	// No model_type, but architectures present; no _name_or_path ⇒ dir name.
	files := map[string]string{
		"mistral/config.json":       `{"architectures":["MistralForCausalLM"]}`,
		"mistral/pytorch_model.bin": tinyWeights,
	}
	got := run(t, NewHFDir(), files, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if got[0].Claim.Name != "mistral" {
		t.Errorf("name = %q, want dir name mistral", got[0].Claim.Name)
	}
	if got[0].Claim.Model.Architecture != "MistralForCausalLM" {
		t.Errorf("architecture = %q", got[0].Claim.Model.Architecture)
	}
	if got[0].Claim.Model.Format != "pytorch" {
		t.Errorf("format = %q, want pytorch", got[0].Claim.Model.Format)
	}
}

func TestHFDir_SkipNonModelConfig(t *testing.T) {
	// A config.json that is not a model config (no model_type/architectures)
	// must be skipped even with a weights file alongside.
	files := map[string]string{
		"pkg/config.json":       `{"name":"my-app","version":"1.0"}`,
		"pkg/model.safetensors": tinyWeights,
	}
	if got := run(t, NewHFDir(), files, nil); len(got) != 0 {
		t.Fatalf("want 0 findings for non-model config, got %d: %+v", len(got), got)
	}
}

func TestHFDir_SkipNoWeights(t *testing.T) {
	files := map[string]string{
		"m/config.json": `{"model_type":"gpt2"}`,
	}
	if got := run(t, NewHFDir(), files, nil); len(got) != 0 {
		t.Fatalf("want 0 findings without weights, got %d", len(got))
	}
}

func TestHFDir_ShardedDedup(t *testing.T) {
	// Multiple shard files ⇒ still exactly ONE component.
	files := map[string]string{
		"big/config.json":                      `{"model_type":"llama"}`,
		"big/model-00001-of-00003.safetensors": tinyWeights,
		"big/model-00002-of-00003.safetensors": tinyWeights,
		"big/model-00003-of-00003.safetensors": tinyWeights,
	}
	got := run(t, NewHFDir(), files, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 deduped finding, got %d", len(got))
	}
	if got[0].Claim.Model.Format != "safetensors" {
		t.Errorf("format = %q", got[0].Claim.Model.Format)
	}
}

func TestHFDir_Diffusers(t *testing.T) {
	files := map[string]string{
		"sd/model_index.json":                         `{"_class_name":"StableDiffusionPipeline","_diffusers_version":"0.30.0"}`,
		"sd/unet/diffusion_pytorch_model.safetensors": tinyWeights,
	}
	got := run(t, NewHFDir(), files, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 diffusers finding, got %d", len(got))
	}
	if got[0].Claim.Name != "sd" {
		t.Errorf("name = %q, want sd", got[0].Claim.Name)
	}
	if got[0].Claim.Model.Architecture != "StableDiffusionPipeline" {
		t.Errorf("architecture = %q", got[0].Claim.Model.Architecture)
	}
}

func TestHFDir_ConfigWinsOverModelIndexSameDir(t *testing.T) {
	// config.json and model_index.json in the same dir ⇒ one component.
	files := map[string]string{
		"d/config.json":       `{"model_type":"llama"}`,
		"d/model_index.json":  `{"_class_name":"SomePipeline"}`,
		"d/model.safetensors": tinyWeights,
	}
	got := run(t, NewHFDir(), files, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Claim.Model.Architecture != "llama" {
		t.Errorf("architecture = %q, want config.json to win", got[0].Claim.Model.Architecture)
	}
}

func TestHFDir_GarbageConfigNoPanic(t *testing.T) {
	files := map[string]string{
		"x/config.json":       "\xff\xfe not json at all {",
		"x/model.safetensors": tinyWeights,
	}
	if got := run(t, NewHFDir(), files, nil); len(got) != 0 {
		t.Fatalf("want 0 findings for garbage, got %d", len(got))
	}
}

// ── AdapterLink ─────────────────────────────────────────────────────────────

func TestAdapterLink_DerivedFrom(t *testing.T) {
	files := map[string]string{
		"lora/adapter_config.json": `{"base_model_name_or_path":"meta-llama/Llama-2-7b-hf","peft_type":"LORA"}`,
	}
	got := run(t, NewAdapterLink(), files, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Claim.Kind != airom.KindLocalModelFile || f.Claim.Name != "lora" {
		t.Errorf("claim = %+v, want local-model-file named lora", f.Claim)
	}
	if f.Claim.Model == nil || f.Claim.Model.BaseModel != "meta-llama/Llama-2-7b-hf" {
		t.Errorf("baseModel = %+v", f.Claim.Model)
	}
	if len(f.Relations) != 1 {
		t.Fatalf("want 1 relation, got %d", len(f.Relations))
	}
	rel := f.Relations[0]
	if rel.Type != airom.RelDerivedFrom {
		t.Errorf("relation type = %q, want derived-from", rel.Type)
	}
	if rel.Target.Kind != airom.KindLocalModelFile || rel.Target.Name != "meta-llama/Llama-2-7b-hf" {
		t.Errorf("target = %+v", rel.Target)
	}
	if f.Occurrence.Fields["peft_type"] != "LORA" {
		t.Errorf("peft_type field = %q", f.Occurrence.Fields["peft_type"])
	}
}

func TestAdapterLink_NoBaseNoRelation(t *testing.T) {
	files := map[string]string{
		"lora/adapter_config.json": `{"peft_type":"LORA"}`,
	}
	got := run(t, NewAdapterLink(), files, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if len(got[0].Relations) != 0 {
		t.Errorf("want no relation without a base, got %+v", got[0].Relations)
	}
}

// ── ConfigBind ──────────────────────────────────────────────────────────────

func TestConfigBind_JSONWithModelRef(t *testing.T) {
	files := map[string]string{
		"m/generation_config.json": `{"temperature":0.7,"top_p":0.9,"max_new_tokens":256,"do_sample":true,"_name_or_path":"my-model"}`,
	}
	got := run(t, NewConfigBind(), files, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Claim.Kind != airom.KindAIConfig || f.Claim.Name != "generation_config.json" {
		t.Errorf("claim = %+v", f.Claim)
	}
	wantFields := map[string]string{
		"param.temperature":    "0.7",
		"param.top_p":          "0.9",
		"param.max_new_tokens": "256",
		"param.do_sample":      "true",
	}
	for k, v := range wantFields {
		if f.Occurrence.Fields[k] != v {
			t.Errorf("field %q = %q, want %q", k, f.Occurrence.Fields[k], v)
		}
	}
	if len(f.Relations) != 1 || f.Relations[0].Type != airom.RelConfigures {
		t.Fatalf("want 1 configures relation, got %+v", f.Relations)
	}
	if f.Relations[0].Target.Name != "my-model" {
		t.Errorf("target name = %q, want my-model", f.Relations[0].Target.Name)
	}
	if f.Occurrence.Confidence != 0.7 {
		t.Errorf("confidence = %v, want 0.7", f.Occurrence.Confidence)
	}
}

func TestConfigBind_NoModelRefStandalone(t *testing.T) {
	files := map[string]string{
		"m/generation_config.json": `{"temperature":0.5}`,
	}
	got := run(t, NewConfigBind(), files, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 standalone finding, got %d", len(got))
	}
	if len(got[0].Relations) != 0 {
		t.Errorf("want no edge without a model ref, got %+v", got[0].Relations)
	}
	if got[0].Occurrence.Fields["param.temperature"] != "0.5" {
		t.Errorf("param.temperature = %q", got[0].Occurrence.Fields["param.temperature"])
	}
}

func TestConfigBind_YAML(t *testing.T) {
	files := map[string]string{
		"cfg/my_generation_config.yaml": "temperature: 0.5\ntop_k: 40\nmodel: gpt-4\n",
	}
	got := run(t, NewConfigBind(), files, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Occurrence.Fields["param.temperature"] != "0.5" {
		t.Errorf("temperature = %q", f.Occurrence.Fields["param.temperature"])
	}
	if f.Occurrence.Fields["param.top_k"] != "40" {
		t.Errorf("top_k = %q, want 40", f.Occurrence.Fields["param.top_k"])
	}
	if len(f.Relations) != 1 || f.Relations[0].Target.Name != "gpt-4" {
		t.Fatalf("want configures→gpt-4, got %+v", f.Relations)
	}
}

func TestConfigBind_SkipEmptyConfig(t *testing.T) {
	files := map[string]string{
		"m/generation_config.json": `{"unrelated":"x"}`,
	}
	if got := run(t, NewConfigBind(), files, nil); len(got) != 0 {
		t.Fatalf("want 0 findings for a config with no params or model ref, got %d", len(got))
	}
}

// ── RAGLink ─────────────────────────────────────────────────────────────────

func embFinding() detect.Finding {
	return detect.Finding{
		Claim: detect.ComponentClaim{Kind: airom.KindEmbeddingModel, Name: "text-embedding-3-large"},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Path: "rag/index.py", Line: 12},
			DetectorID: "rules/openai/embeddings",
			Method:     airom.MethodSourceCode,
			Confidence: 0.9,
		},
	}
}

func vdbFinding() detect.Finding {
	return detect.Finding{
		Claim: detect.ComponentClaim{Kind: airom.KindVectorDB, Name: "pinecone"},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Path: "rag/store.py", Line: 4},
			DetectorID: "rules/pinecone",
			Method:     airom.MethodSourceCode,
			Confidence: 0.85,
		},
	}
}

func TestRAGLink_Synthesizes(t *testing.T) {
	view := detect.NewFindingsView([]detect.Finding{embFinding(), vdbFinding()})
	got := run(t, NewRAGLink(), nil, view)
	if len(got) != 1 {
		t.Fatalf("want 1 rag-pipeline finding, got %d", len(got))
	}
	f := got[0]
	if f.Claim.Kind != airom.KindRAGPipeline || f.Claim.Name != "rag-pipeline" {
		t.Errorf("claim = %+v", f.Claim)
	}
	if f.Occurrence.Location != (airom.Location{Path: "rag/index.py", Line: 12}) {
		t.Errorf("anchor = %+v, want the embedding finding's location", f.Occurrence.Location)
	}
	if f.Occurrence.Confidence != 0.6 {
		t.Errorf("confidence = %v, want 0.6", f.Occurrence.Confidence)
	}
	rels := map[airom.RelType]detect.TargetHint{}
	for _, r := range f.Relations {
		rels[r.Type] = r.Target
	}
	if h, ok := rels[airom.RelEmbedsWith]; !ok || h.Kind != airom.KindEmbeddingModel || h.Name != "text-embedding-3-large" {
		t.Errorf("embeds-with = %+v", rels[airom.RelEmbedsWith])
	}
	if h, ok := rels[airom.RelContains]; !ok || h.Kind != airom.KindVectorDB || h.Name != "pinecone" {
		t.Errorf("contains = %+v", rels[airom.RelContains])
	}
}

func TestRAGLink_MissingHalfEmitsNothing(t *testing.T) {
	onlyEmb := detect.NewFindingsView([]detect.Finding{embFinding()})
	if got := run(t, NewRAGLink(), nil, onlyEmb); len(got) != 0 {
		t.Fatalf("want nothing with no vector-db, got %d", len(got))
	}
	onlyVdb := detect.NewFindingsView([]detect.Finding{vdbFinding()})
	if got := run(t, NewRAGLink(), nil, onlyVdb); len(got) != 0 {
		t.Fatalf("want nothing with no embedding model, got %d", len(got))
	}
	empty := detect.NewFindingsView(nil)
	if got := run(t, NewRAGLink(), nil, empty); len(got) != 0 {
		t.Fatalf("want nothing with an empty view, got %d", len(got))
	}
}
