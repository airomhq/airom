package app

import (
	"context"

	"github.com/airomhq/airom/internal/compliance"
	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"

	// Register the built-in writers (init() side effects).
	_ "github.com/airomhq/airom/internal/writer/cdx"
	_ "github.com/airomhq/airom/internal/writer/compliancew"
	_ "github.com/airomhq/airom/internal/writer/nativejson"
	_ "github.com/airomhq/airom/internal/writer/sarifw"
	_ "github.com/airomhq/airom/internal/writer/spdxw"
	_ "github.com/airomhq/airom/internal/writer/tablew"
	_ "github.com/airomhq/airom/internal/writer/vexw"
	_ "github.com/airomhq/airom/internal/writer/yamlw"
)

// formatNames maps CLI output formats to writer registry names.
var formatNames = map[OutputFormat]string{
	FormatTable:      "table",
	FormatJSON:       "json",
	FormatCycloneDX:  "cyclonedx",
	FormatSARIF:      "sarif",
	FormatYAML:       "yaml",
	FormatCompliance: "compliance",
	FormatVEX:        "vex",
	FormatSPDX:       "spdx",
}

// emit renders the assembled inventory to every configured output
// (docs/cli.md multi-output). It applies the presentation-layer
// --min-confidence filter (§9: filtering is presentation, never assembly),
// logs the honesty channel, and — when --stats is off — drops the volatile
// timing/detector stats so output is reproducible.
func emit(ctx context.Context, inv *airom.Inventory, cfg *Config) error {
	logDiagnostics(inv, cfg)

	if cfg.MinConfidence > 0 {
		inv = presentationFilter(inv, cfg)
	}
	if !cfg.Stats {
		inv.Stats = airom.ScanStats{
			FilesWalked:    inv.Stats.FilesWalked,
			FilesProcessed: inv.Stats.FilesProcessed,
			FilesFailed:    inv.Stats.FilesFailed,
			// The assurance fields survive for the same reason Warnings do:
			// they say what the scan did NOT see (ignored files, pruned
			// directories, truncated reads, overlays that never ran, what the
			// confidence numbers mean). Dropping them would make a partial
			// scan byte-identical to a complete one.
			FilesIgnored:    inv.Stats.FilesIgnored,
			DirsPruned:      inv.Stats.DirsPruned,
			FilesTruncated:  inv.Stats.FilesTruncated,
			Enrichment:      inv.Stats.Enrichment,
			ConfidenceModel: inv.Stats.ConfidenceModel,
			// Warnings survive the reset. They are the honesty channel, not a
			// volatile timing counter: they record where the scan could NOT see
			// (an unreachable advisory database, an unusable lifecycle catalog),
			// and dropping them makes a degraded scan byte-identical to a clean
			// one. Under `-q` the log copy is suppressed too, so this would be
			// the only surviving trace.
			Warnings: inv.Stats.Warnings,
		}
	}

	outputs := make([]writer.Output, len(cfg.Outputs))
	for i, o := range cfg.Outputs {
		outputs[i] = writer.Output{Format: formatNames[o.Format], Path: o.Path}
	}

	opts := writer.Options{
		CDXVersion:   cfg.CDXVersion,
		SARIFStrict:  cfg.SARIFStrictKinds,
		TableWide:    cfg.Wide,
		IncludeTests: cfg.IncludeTests,
	}
	return writer.Fanout(ctx, inv, outputs, opts, stdout)
}

// presentationFilter applies the --min-confidence presentation filter and
// keeps the emitted inventory internally consistent. Because the compliance
// overlay describes the inventory being emitted, it is RE-MAPPED over the
// filtered components — otherwise a control would reference (or claim a scored
// "met" against) components the filter just dropped, asserting evidence that
// is not in the BOM. Framework ids were validated in the pipeline, so a re-map
// error is not expected; on the off chance, the stale overlay is dropped
// rather than emitted with dangling evidence.
func presentationFilter(inv *airom.Inventory, cfg *Config) *airom.Inventory {
	out := filterByConfidence(inv, cfg.MinConfidence)
	if len(cfg.Compliance) > 0 {
		if results, err := compliance.Evaluate(out, cfg.Compliance, cfg.IncludeTests); err == nil {
			out.Compliance = results
		} else {
			out.Compliance = nil
		}
	}
	return out
}

// filterByConfidence returns a copy of inv keeping the application root and
// components at or above min, plus relationships whose endpoints both
// survive. Assembly is never mutated (§9).
func filterByConfidence(inv *airom.Inventory, minConf float64) *airom.Inventory {
	kept := make([]airom.Component, 0, len(inv.Components))
	alive := map[airom.ID]bool{}
	for _, c := range inv.Components {
		if c.Kind == airom.KindApplication || float64(c.Confidence) >= minConf {
			kept = append(kept, c)
			alive[c.ID] = true
		}
	}
	var rels []airom.Relationship
	for _, r := range inv.Relationships {
		if alive[r.From] && alive[r.To] {
			rels = append(rels, r)
		}
	}
	out := *inv
	out.Components = kept
	out.Relationships = rels
	return &out
}
