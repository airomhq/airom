package project

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"sort"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// ConfigBind attaches a separated generation/model config to the model it
// names via a CONFIGURES edge, carrying the sampling parameters on the
// occurrence (§9.5). When the config names no model it still emits the
// ai-config component standalone — a refusal to guess an edge, never a
// fabricated one.
type ConfigBind struct{}

// NewConfigBind returns the config-binding ProjectDetector.
func NewConfigBind() *ConfigBind { return &ConfigBind{} }

// ID is the stable detector identity (SARIF ruleId).
func (*ConfigBind) ID() string { return "project/configbind" }

// Version participates in cache keys; bump on any behavior change.
func (*ConfigBind) Version() int { return 1 }

// Selector is ignored for project detectors — they pull via the Resolver.
func (*ConfigBind) Selector() detect.Selector { return detect.Selector{} }

// genParamKeys are the generation parameters captured onto the occurrence as
// "param.<name>" fields.
var genParamKeys = []string{
	"temperature", "top_p", "top_k",
	"max_tokens", "max_new_tokens", "max_length",
	"do_sample", "num_beams",
	"repetition_penalty", "presence_penalty", "frequency_penalty", "typical_p",
}

// modelRefKeys are the fields that may name the configured model, in priority
// order.
var modelRefKeys = []string{"_name_or_path", "model", "model_name"}

// DetectProject emits one ai-config component per generation/model config,
// with a CONFIGURES edge to the named model when one is present.
func (cb *ConfigBind) DetectProject(ctx context.Context, r detect.Resolver, _ *detect.FindingsView) ([]detect.Finding, error) {
	refs, err := r.FilesByGlob(ctx,
		"**/generation_config.json",
		"**/*generation*config*.yaml",
		"**/*generation*config*.yml",
		"**/model_config.json",
		"**/model_config.yaml",
		"**/model_config.yml",
	)
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
		m, ok := parseConfig(ref.Path, data)
		if !ok {
			continue
		}

		var fields map[string]string
		for _, k := range genParamKeys {
			if v, present := m[k]; present {
				if fields == nil {
					fields = map[string]string{}
				}
				fields["param."+k] = scalarString(v)
			}
		}
		modelRef := stringField(m, modelRefKeys)

		// A config with neither a recognized parameter nor a model reference
		// is not a generation config — skip it rather than emit noise.
		if len(fields) == 0 && modelRef == "" {
			continue
		}

		f := detect.Finding{
			Claim: detect.ComponentClaim{
				Kind: airom.KindAIConfig,
				Name: path.Base(ref.Path),
			},
			Occurrence: airom.Occurrence{
				Location:   airom.Location{Path: ref.Path},
				DetectorID: cb.ID(),
				Method:     airom.MethodConfig,
				Confidence: 0.7,
				Fields:     fields,
			},
		}
		if modelRef != "" {
			f.Relations = []detect.RelationClaim{{
				Type:   airom.RelConfigures,
				Target: detect.TargetHint{Kind: airom.KindLocalModelFile, Name: modelRef},
			}}
		}
		out = append(out, f)
	}
	return out, nil
}

// parseConfig decodes a JSON or YAML config into a top-level mapping. A file
// whose top level is not an object (or is malformed) yields ok=false.
func parseConfig(p string, data []byte) (map[string]any, bool) {
	m := map[string]any{}
	if path.Ext(p) == ".json" {
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, false
		}
		return m, true
	}
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	return m, true
}

// stringField returns the first key's value that is a non-empty string.
func stringField(m map[string]any, keys []string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// scalarString renders a scalar config value as a stable string. Integral
// floats print without a decimal so JSON's 256.0 reads as "256".
func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		if !math.IsInf(t, 0) && !math.IsNaN(t) && t == math.Trunc(t) {
			return strconv.FormatFloat(t, 'f', -1, 64)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprintf("%v", t)
	}
}
