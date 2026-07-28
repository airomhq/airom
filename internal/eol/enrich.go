package eol

import (
	"sort"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
)

// modelIDProp is where the assembler records the provider-native model id
// ("gpt-4-32k"), which is what a deprecation page names. Component.Name is the
// fallback: the two usually agree, but the raw id is authoritative.
const modelIDProp = "airom:model.id"

// Enrich attaches a Lifecycle to every model component the catalog knows about,
// mutating inv in place, and returns how many components it matched.
//
// It is deliberately narrow. Only hosted model references are matched: those
// are the components whose lifetime a provider controls unilaterally, where a
// retirement means the application stops working on a date. A local weights
// file on disk does not stop working because a vendor said so.
//
// Components with no catalog record are left untouched — no Lifecycle at all,
// which reads as "unknown". This function never writes a "supported" claim it
// cannot source.
func Enrich(inv *airom.Inventory, cat *Catalog, on airom.Date) int {
	if inv == nil || cat == nil {
		return 0
	}
	matched := 0
	for i := range inv.Components {
		c := &inv.Components[i]
		if !eligible(c.Kind) {
			continue
		}
		provider, ok := c.Provider.Value()
		if !ok || strings.TrimSpace(provider) == "" {
			continue // no provider → nothing to key on
		}
		lc := cat.Lookup(provider, modelID(c), on)
		if lc == nil {
			continue
		}
		c.EOL = lc
		matched++
	}
	if w := cat.StalenessWarning(on); w != "" {
		inv.Stats.Warnings = append(inv.Stats.Warnings, w)
		sort.Strings(inv.Stats.Warnings)
	}
	return matched
}

// eligible reports whether a component kind is provider-hosted, i.e. whether a
// vendor retirement announcement can break it.
func eligible(k airom.ComponentKind) bool {
	return k == airom.KindHostedLLM || k == airom.KindEmbeddingModel
}

// modelID returns the provider-native id to match on: the airom:model.id prop
// when the assembler recorded one, else the component name.
func modelID(c *airom.Component) string {
	for _, p := range c.Props {
		if p.Name == modelIDProp && strings.TrimSpace(p.Value) != "" {
			return p.Value
		}
	}
	return c.Name
}
