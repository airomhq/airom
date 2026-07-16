package project

import (
	"context"
	"encoding/json"
	"path"
	"sort"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// AdapterLink turns a PEFT/LoRA adapter_config.json into a local-model-file
// component with a DERIVED_FROM edge to its base model (§17). The edge names
// the base by base_model_name_or_path; the assembler resolves it if that base
// exists in the scan and warns otherwise — this detector never fabricates the
// base component.
type AdapterLink struct{}

// NewAdapterLink returns the adapter-lineage ProjectDetector.
func NewAdapterLink() *AdapterLink { return &AdapterLink{} }

// ID is the stable detector identity (SARIF ruleId).
func (*AdapterLink) ID() string { return "project/adapter" }

// Version participates in cache keys; bump on any behavior change.
func (*AdapterLink) Version() int { return 1 }

// Selector is ignored for project detectors — they pull via the Resolver.
func (*AdapterLink) Selector() detect.Selector { return detect.Selector{} }

// DetectProject emits one adapter component per adapter_config.json, each with
// a DERIVED_FROM relation to its declared base model.
func (a *AdapterLink) DetectProject(ctx context.Context, r detect.Resolver, _ *detect.FindingsView) ([]detect.Finding, error) {
	refs, err := r.FilesByGlob(ctx, "**/adapter_config.json")
	if err != nil {
		return nil, err
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Path < refs[j].Path })

	var out []detect.Finding
	for _, ref := range refs {
		data, err := openAll(r, ref.Path)
		if err != nil {
			continue
		}
		var cfg map[string]json.RawMessage
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}
		base := jsonString(cfg, "base_model_name_or_path")
		peft := jsonString(cfg, "peft_type")

		occ := airom.Occurrence{
			Location:   airom.Location{Path: ref.Path},
			DetectorID: a.ID(),
			Method:     airom.MethodConfig,
			Confidence: 0.9,
		}
		if peft != "" {
			occ.Fields = map[string]string{"peft_type": peft}
		}
		f := detect.Finding{
			Claim: detect.ComponentClaim{
				Kind:     airom.KindLocalModelFile,
				Name:     dirNameFor(path.Dir(ref.Path)),
				Provider: "local",
				Model:    &detect.ModelClaim{BaseModel: base},
			},
			Occurrence: occ,
		}
		if base != "" {
			// The base of a locally present model is a local weights dir; a
			// hub-id base with no local copy simply warns (refusal over
			// fabrication, §9.5).
			f.Relations = []detect.RelationClaim{{
				Type:   airom.RelDerivedFrom,
				Target: detect.TargetHint{Kind: airom.KindLocalModelFile, Name: base},
			}}
		}
		out = append(out, f)
	}
	return out, nil
}
