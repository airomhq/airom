package project

import (
	"context"
	"encoding/json"
	"path"
	"sort"
	"strings"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// HFDir assembles a HuggingFace / diffusers model DIRECTORY (a config plus its
// sibling weight shards) into ONE local-model-file component — collapsing the
// "N shard files" problem the streaming phase cannot see across (§3, §17). It
// keys off config.json (transformers) and model_index.json (diffusers).
type HFDir struct{}

// NewHFDir returns the HuggingFace-directory assembler ProjectDetector.
func NewHFDir() *HFDir { return &HFDir{} }

// ID is the stable detector identity (SARIF ruleId).
func (*HFDir) ID() string { return "project/hfdir" }

// Version participates in cache keys; bump on any behavior change.
func (*HFDir) Version() int { return 1 }

// Selector is ignored for project detectors — they pull via the Resolver.
func (*HFDir) Selector() detect.Selector { return detect.Selector{} }

// transformerWeights are the same-directory weight patterns a transformers
// config.json is assembled against.
var transformerWeights = []string{
	"model.safetensors",
	"pytorch_model.bin",
	"model-*-of-*.safetensors", // sharded checkpoints (any shard proves presence)
	"*.gguf",
}

// diffuserWeights are the weight patterns for a diffusers pipeline: its
// sub-model weights live one directory down (unet/, vae/, …), so both the
// pipeline root and one subdirectory level are checked.
var diffuserWeights = []string{
	"*.safetensors", "*.bin",
	"*/*.safetensors", "*/*.bin", "*/*.gguf",
}

// DetectProject finds every config.json / model_index.json, and for each that
// names a model AND has a sibling weights file emits ONE local-model-file
// component for its directory. A config.json with neither model_type nor
// architectures is not a model config and is skipped.
func (h *HFDir) DetectProject(ctx context.Context, r detect.Resolver, _ *detect.FindingsView) ([]detect.Finding, error) {
	refs, err := r.FilesByGlob(ctx, "**/config.json", "**/model_index.json")
	if err != nil {
		return nil, err
	}
	// Deterministic order; within a directory "config.json" sorts before
	// "model_index.json", so a transformers config wins the directory.
	sort.Slice(refs, func(i, j int) bool { return refs[i].Path < refs[j].Path })

	var out []detect.Finding
	emitted := map[string]bool{} // one component per directory
	for _, ref := range refs {
		base := path.Base(ref.Path)
		if base != "config.json" && base != "model_index.json" {
			continue
		}
		dir := path.Dir(ref.Path)
		if emitted[dir] {
			continue
		}
		f, ok := h.assemble(ctx, r, ref.Path, dir, base)
		if !ok {
			continue
		}
		emitted[dir] = true
		out = append(out, f)
	}
	return out, nil
}

// assemble parses one config file and, when it identifies a model backed by a
// sibling weights file, builds the directory's single component. The bool is
// false (⇒ skip) for a non-model config or a config with no weights.
func (h *HFDir) assemble(ctx context.Context, r detect.Resolver, cfgPath, dir, base string) (detect.Finding, bool) {
	data, err := openAll(r, cfgPath)
	if err != nil {
		return detect.Finding{}, false
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		return detect.Finding{}, false
	}

	var arch string
	var weights []string
	if base == "model_index.json" {
		arch = jsonString(cfg, "_class_name")
		if arch == "" {
			return detect.Finding{}, false // not a diffusers pipeline
		}
		weights = diffuserWeights
	} else {
		modelType := jsonString(cfg, "model_type")
		archs := jsonStrings(cfg, "architectures")
		if modelType == "" && len(archs) == 0 {
			return detect.Finding{}, false // not a model config
		}
		arch = modelType
		if arch == "" {
			arch = archs[0]
		}
		weights = transformerWeights
	}

	ext, ok := firstWeights(ctx, r, dir, weights)
	if !ok {
		return detect.Finding{}, false
	}

	name := jsonString(cfg, "_name_or_path")
	if name == "" {
		name = dirNameFor(dir)
	}

	return detect.Finding{
		Claim: detect.ComponentClaim{
			Kind:     airom.KindLocalModelFile,
			Name:     name,
			Provider: "local",
			Model:    &detect.ModelClaim{Architecture: arch, Format: weightsFormat(ext)},
		},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Path: cfgPath}, // Line 0 = whole file
			DetectorID: h.ID(),
			Method:     airom.MethodBinary,
			Confidence: 0.9,
		},
	}, true
}

// firstWeights reports whether any of rels (joined onto dir) matches a file,
// returning the lowercase extension of the lexicographically first match so
// the format is deterministic regardless of resolver order.
func firstWeights(ctx context.Context, r detect.Resolver, dir string, rels []string) (ext string, ok bool) {
	pats := make([]string, 0, len(rels))
	for _, rel := range rels {
		pats = append(pats, joinPat(dir, rel))
	}
	refs, err := r.FilesByGlob(ctx, pats...)
	if err != nil || len(refs) == 0 {
		return "", false
	}
	best := refs[0].Path
	for _, ref := range refs[1:] {
		if ref.Path < best {
			best = ref.Path
		}
	}
	return strings.ToLower(path.Ext(best)), true
}

// joinPat prefixes a directory onto a relative glob, leaving the scan root
// unprefixed so patterns stay source-root-relative.
func joinPat(dir, rel string) string {
	if dir == "" || dir == "." {
		return rel
	}
	return dir + "/" + rel
}

// weightsFormat maps a weight-file extension to a model format label.
func weightsFormat(ext string) string {
	switch ext {
	case ".safetensors":
		return "safetensors"
	case ".gguf":
		return "gguf"
	case ".bin", ".pt", ".pth":
		return "pytorch"
	default:
		return strings.TrimPrefix(ext, ".")
	}
}
