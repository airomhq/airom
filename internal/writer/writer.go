// Package writer defines the output stage (ARCHITECTURE.md §11): a Writer is
// a pure function from *airom.Inventory to bytes (invariant P5). Every
// format is a projection of the same assembled graph, mapped per
// docs/mapping.md. The Inventory is small, so rendering is in-memory and
// deterministic (P7). Multi-output is first-class: the repeatable
// -o fmt[=path] flag emits several formats from one scan.
package writer

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"

	"github.com/Roro1727/airom/pkg/airom"
)

// Options parameterize format-specific behavior (docs/cli.md flags).
type Options struct {
	CDXVersion  string // "1.6" (default) | "1.7"
	SARIFStrict bool   // kind:"informational" instead of level:"note"
	TableWide   bool   // expand file:line lists in the table
}

// Writer renders an Inventory to one format. Pure: no I/O decisions, no
// reaching back into the engine.
type Writer interface {
	Format() string
	Write(w io.Writer, inv *airom.Inventory) error
}

// factory builds a Writer for a format given options.
type factory func(Options) Writer

// registry maps format names to factories. Writers self-register in init().
var registry = map[string]factory{}

// Register adds a writer factory. Called from each writer package's init().
func Register(format string, f factory) { registry[format] = f }

// New returns a writer for a format, or an error for an unknown format.
func New(format string, opts Options) (Writer, error) {
	f, ok := registry[format]
	if !ok {
		return nil, fmt.Errorf("unknown output format %q", format)
	}
	return f(opts), nil
}

// Output is one resolved destination: a format plus a file path ("" =
// stdout).
type Output struct {
	Format string
	Path   string
}

// Fanout renders inv to every output in one pass. A single stdout writer is
// allowed; file destinations are created (truncating). stdout is the
// injectable stdout sink.
func Fanout(_ context.Context, inv *airom.Inventory, outputs []Output, opts Options, stdout io.Writer) error {
	for _, o := range outputs {
		wr, err := New(o.Format, opts)
		if err != nil {
			return err
		}
		dst := stdout
		if o.Path != "" {
			f, err := os.Create(o.Path) // #nosec G304 -- user-specified output path
			if err != nil {
				return fmt.Errorf("create %s: %w", o.Path, err)
			}
			defer func() { _ = f.Close() }()
			dst = f
		}
		if err := wr.Write(dst, inv); err != nil {
			return fmt.Errorf("write %s: %w", o.Format, err)
		}
	}
	return nil
}

// ── Shared serialization helpers (docs/mapping.md §6) ───────────────────────

// FormatConfidence renders a confidence per §6.2: round half-to-even to 4
// fractional digits, then trim trailing zeros ("0.9", "0.975", "1").
// Deterministic (P7).
func FormatConfidence(c airom.Confidence) string {
	v := math.RoundToEven(float64(c)*1e4) / 1e4
	s := strconv.FormatFloat(v, 'f', 4, 64)
	// trim trailing zeros, then a dangling dot
	for len(s) > 0 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	if len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

// ConfidenceNumber returns the §6.2-rounded confidence as a float for
// formats that carry it as a JSON number (CDX identity, SARIF bags).
func ConfidenceNumber(c airom.Confidence) float64 {
	v, _ := strconv.ParseFloat(FormatConfidence(c), 64)
	return v
}

// ModelKind reports whether a kind maps to a CDX machine-learning-model
// (§3.3 / §4) — the kinds that carry airom:model.* properties and a
// modelCard.
func ModelKind(k airom.ComponentKind) bool {
	switch k {
	case airom.KindHostedLLM, airom.KindLocalModelFile, airom.KindEmbeddingModel:
		return true
	default:
		return false
	}
}
