// Package rules embeds the built-in AIROM rule packs (ARCHITECTURE.md §6.3):
// the offline-by-construction default detection vocabulary, compiled into
// the binary and versioned with each release. Only the top-level pack YAML
// per category is embedded — testdata fixtures are excluded from the shipped
// binary.
package rules

import (
	"embed"
	"io/fs"
)

//go:embed models/*.yaml embeddings/*.yaml frameworks/*.yaml vectordb/*.yaml infra/*.yaml params/*.yaml prompts/*.yaml datasets/*.yaml
var packs embed.FS

// FS returns the embedded rule-pack filesystem, rooted so that entries are
// "<category>/<pack>.yaml" — the layout ruleengine.Load walks.
func FS() fs.FS { return packs }
