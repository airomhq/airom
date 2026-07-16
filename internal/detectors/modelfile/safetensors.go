package modelfile

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strconv"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Safetensors detects safetensors weight files by reading their JSON header
// only. The header maps tensor names to {dtype, shape, data_offsets}; the
// detector sums the parameter count over every tensor and infers a dominant
// dtype as the precision/quantization label, never touching the tensor data
// that follows.
type Safetensors struct{}

// NewSafetensors constructs the safetensors detector.
func NewSafetensors() *Safetensors { return &Safetensors{} }

// ID returns the stable detector identity.
func (*Safetensors) ID() string { return "modelfile/safetensors" }

// Version is the detector's behavior version.
func (*Safetensors) Version() int { return 1 }

// Selector routes .safetensors files.
func (*Safetensors) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".safetensors"},
		Need:       detect.NeedContent,
	}
}

// stTensor is one tensor entry in a safetensors header.
type stTensor struct {
	Dtype       string  `json:"dtype"`
	Shape       []int64 `json:"shape"`
	DataOffsets []int64 `json:"data_offsets"`
}

// stInfo is the header-only summary of a safetensors file.
type stInfo struct {
	paramCount   int64
	haveParam    bool
	dominant     string
	architecture string
	metaFormat   string
	tensorCount  int
}

// DetectFile parses the safetensors header and emits one whole-file finding.
// A missing, oversized, or malformed header yields no finding and no error;
// the parser never allocates against the attacker-controlled header length.
func (d *Safetensors) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, nil //nolint:nilerr // unreadable file degrades to no finding, not an error
	}
	info, ok := parseSafetensors(content)
	if !ok {
		return nil, nil
	}

	model := &detect.ModelClaim{Format: "safetensors"}
	if info.haveParam {
		model.ParamCount = info.paramCount
	}
	if info.dominant != "" {
		model.Quantization = info.dominant
	}
	if info.architecture != "" {
		model.Architecture = info.architecture
	}

	fields := map[string]string{"tensor_count": strconv.Itoa(info.tensorCount)}
	if info.dominant != "" {
		fields["dtype"] = info.dominant
	}
	if info.haveParam {
		fields["parameter_count"] = strconv.FormatInt(info.paramCount, 10)
	}
	if info.metaFormat != "" {
		fields["metadata.format"] = info.metaFormat
	}
	if info.architecture != "" {
		fields["architecture"] = info.architecture
	}

	return []detect.Finding{{
		Claim: detect.ComponentClaim{
			Kind:     airom.KindLocalModelFile,
			Name:     f.Base(),
			Provider: "local",
			Model:    model,
		},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{}, // whole file; engine fills Path and SHA-256
			Method:     airom.MethodBinary,
			Confidence: airom.Confidence(0.95),
			Fields:     fields,
		},
	}}, nil
}

// parseSafetensors reads the 8-byte header length, bounds it, then parses the
// JSON header object. It returns ok==false when the input is not a
// structurally valid safetensors file.
func parseSafetensors(b []byte) (stInfo, bool) {
	c := cursor{b: b}
	hlen, ok := c.u64()
	if !ok || hlen == 0 || hlen > maxSafetensorsHeader {
		return stInfo{}, false
	}
	raw, ok := c.take(hlen)
	if !ok {
		return stInfo{}, false // header claims more bytes than the file holds
	}

	var header map[string]json.RawMessage
	if err := json.Unmarshal(raw, &header); err != nil {
		return stInfo{}, false
	}

	var info stInfo
	byDtype := map[string]int64{}
	for name, rawEntry := range header {
		if name == "__metadata__" {
			applySafetensorsMetadata(&info, rawEntry)
			continue
		}
		if info.tensorCount >= maxSafetensorsTensors {
			break
		}
		var t stTensor
		if err := json.Unmarshal(rawEntry, &t); err != nil {
			continue // skip an entry that is not a tensor descriptor
		}
		info.tensorCount++
		n, ok := productShape(t.Shape)
		if !ok {
			continue
		}
		if t.Dtype != "" {
			byDtype[t.Dtype] += n
		}
		if !info.haveParam {
			info.paramCount = 0
			info.haveParam = true
		}
		if info.paramCount <= math.MaxInt64-n {
			info.paramCount += n
		}
	}

	info.dominant = dominantDtype(byDtype)
	return info, true
}

// applySafetensorsMetadata reads the optional __metadata__ object for format
// and architecture hints. A non-object metadata value is ignored.
func applySafetensorsMetadata(info *stInfo, raw json.RawMessage) {
	var meta map[string]string
	if err := json.Unmarshal(raw, &meta); err != nil {
		return
	}
	info.metaFormat = meta["format"]
	for _, key := range []string{"architecture", "model_type", "modelspec.architecture"} {
		if v := meta[key]; v != "" {
			info.architecture = v
			break
		}
	}
}

// productShape multiplies a tensor shape into an element count with overflow
// and negative-dimension guards. A zero dimension yields a zero-element
// tensor; an empty shape (a scalar) yields one element.
func productShape(shape []int64) (int64, bool) {
	prod := int64(1)
	for _, d := range shape {
		if d < 0 {
			return 0, false
		}
		if d == 0 {
			return 0, true
		}
		if prod > math.MaxInt64/d {
			return 0, false
		}
		prod *= d
	}
	return prod, true
}

// dominantDtype returns the dtype accounting for the most elements, breaking
// ties by lexicographic order so the result is deterministic regardless of
// map iteration order.
func dominantDtype(byDtype map[string]int64) string {
	if len(byDtype) == 0 {
		return ""
	}
	dtypes := make([]string, 0, len(byDtype))
	for d := range byDtype {
		dtypes = append(dtypes, d)
	}
	sort.Strings(dtypes)
	best := dtypes[0]
	for _, d := range dtypes[1:] {
		if byDtype[d] > byDtype[best] {
			best = d
		}
	}
	return best
}
