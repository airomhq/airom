// Package yamlw writes the native model as YAML (docs/mapping.md): the same
// projection as native JSON, rendered through the JSON representation so the
// key names and tri-state null handling match byte-for-byte in structure.
package yamlw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/Roro1727/airom/internal/writer"
	"github.com/Roro1727/airom/pkg/airom"
)

func init() { writer.Register("yaml", func(writer.Options) writer.Writer { return Writer{} }) }

// Writer renders native YAML.
type Writer struct{}

// Format implements writer.Writer.
func (Writer) Format() string { return "yaml" }

// Write emits the Inventory as YAML. It routes through JSON so the tri-state
// custom marshalers and the exact native key names apply; yaml.v3 then
// key-sorts maps for determinism (P7).
func (Writer) Write(w io.Writer, inv *airom.Inventory) error {
	data, err := json.Marshal(inv)
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}
	// UseNumber keeps numbers as json.Number (a string) instead of float64,
	// which yaml.v3 would render in scientific notation for large int64 fields
	// (e.g. ParamCount, SizeBytes). normalizeNumbers then restores int64/float64
	// typing so whole numbers emit as plain integers — keeping YAML structurally
	// identical to native JSON (P5).
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return fmt.Errorf("reparse inventory: %w", err)
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(normalizeNumbers(generic)); err != nil {
		return err
	}
	return enc.Close()
}

// normalizeNumbers converts json.Number values into int64 where they are
// integral, else float64, so yaml.v3 renders whole numbers as plain integers
// rather than scientific-notation floats. (Phase 10 review, writers-conformance.)
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = normalizeNumbers(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = normalizeNumbers(val)
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	default:
		return v
	}
}
