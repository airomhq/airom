package detect

import "strings"

// IsAIROMConfig reports whether a file's bytes are one of AIROM's OWN
// configuration formats — a rule pack or a model lifecycle catalog — rather
// than an AI asset belonging to the scanned project.
//
// Detectors that classify by filename need this. A rule pack is a YAML file
// full of provider names, model ids, and prompt patterns, so a project that
// keeps its custom packs in `prompts/` had them inventoried as prompt assets:
// the AIBOM listed the user's detection *configuration* as part of the software
// it describes. AIROM's own repository showed the same thing with
// `rules/prompts/prompts.yaml`.
//
// Structural, not path-based, because the path is exactly what misleads here.
// A rule pack is `pack:` + `rules:`; a catalog is `provider:` + `models:` +
// `verified:` — shapes nothing else has, wherever the file happens to live.
//
// Deliberately a top-level-key scan rather than a YAML parse: pkg/airom is the
// public plugin SDK and stays stdlib-only (ARCHITECTURE.md §4), so it cannot
// drag a parser onto every detector author. Only column-0 keys count, which is
// also what makes the check safe — the `rules:` inside a prompt's block scalar
// is indented, so it cannot trigger this and hide a real finding.
func IsAIROMConfig(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	var pack, rules, provider, models, verified bool
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		// Column 0 only: anything indented belongs to a nested structure or a
		// block scalar, and is not a document-level declaration.
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' || line[0] == '-' {
			continue
		}
		key, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "pack":
			pack = true
		case "rules":
			rules = true
		case "provider":
			provider = true
		case "models":
			models = true
		case "verified":
			verified = true
		}
	}
	if pack && rules {
		return true // rule pack
	}
	// A lifecycle catalog. All three are required: `provider:` alone is an
	// ordinary key that a real config file could plausibly carry, and hiding
	// one of those would cost a genuine finding.
	return provider && models && verified
}
