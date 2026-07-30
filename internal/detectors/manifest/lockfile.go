package manifest

import (
	"sort"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

// confLocked is the per-sighting confidence for a lockfile.
//
// It sits between the manifests' confDeclared and installed metadata's
// confInstalled, and the ordering is the point rather than the numbers. A
// manifest records the version that was ASKED FOR and is usually a range; a
// lockfile records the one the resolver PICKED, exactly; installed metadata
// records the one that is actually THERE. The assembler settles version
// conflicts by occurrence confidence, so this ordering is what makes a
// resolved version win over a declared floor when a tree carries both.
const confLocked = airom.Confidence(0.96)

// lockedPkg is one resolved dependency read out of a lockfile.
type lockedPkg struct {
	name    string
	version string
	line    int // 1-based; 0 means whole-file
}

// emitLocked filters resolved packages through the ecosystem's AI catalog and
// builds findings. A lockfile holds the full transitive closure, which is a
// feature here — an AI dependency pulled in by something else is still AI
// running in the application — but it is also why the catalog gate matters
// more here than anywhere else: a lockfile lists thousands of packages.
func emitLocked(pkgs []lockedPkg, cat catalog, ecosystem string, norm func(string) string) []detect.Finding {
	// Sort BEFORE deduping, not after. Callers build this slice by ranging
	// over JSON and YAML maps, whose order Go randomizes per run. A lockfile
	// can list the same name@version twice — npm nests a second copy under a
	// dependent, pnpm repeats one per peer set — and those copies sit on
	// different lines. Deduping an unsorted slice would keep whichever copy
	// map iteration happened to yield first, so the reported line would
	// change between runs of an unchanged scan (P7).
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].name != pkgs[j].name {
			return pkgs[i].name < pkgs[j].name
		}
		if pkgs[i].version != pkgs[j].version {
			return pkgs[i].version < pkgs[j].version
		}
		return pkgs[i].line < pkgs[j].line
	})

	seen := make(map[string]bool, len(pkgs))
	out := make([]detect.Finding, 0, 8)
	for _, p := range pkgs {
		if p.name == "" || p.version == "" {
			continue
		}
		key := norm(p.name)
		ai, ok := cat.lookup(key)
		if !ok {
			continue
		}
		// Each distinct version is a real component — a lockfile resolving two
		// copies of a package at different versions is a fact worth reporting.
		// The same one listed twice is not; the earliest line wins.
		dedupe := key + "@" + p.version
		if seen[dedupe] {
			continue
		}
		seen[dedupe] = true

		f := mkFinding(ai, ai.emitName(key), "", ecosystem, p.version, p.line)
		f.Occurrence.Confidence = confLocked
		out = append(out, f)
	}
	return out
}

// lineOf returns the 1-based line of the first occurrence of needle, or 0
// (whole-file) when it does not appear.
//
// Lockfiles are parsed structurally, which loses byte offsets. Rather than
// point every finding at line 0, the key is located in the raw text — an
// approximate line that lands on the right entry beats no line at all.
func lineOf(content []byte, needle string) int {
	if needle == "" {
		return 0
	}
	i := strings.Index(string(content), needle)
	if i < 0 {
		return 0
	}
	return 1 + strings.Count(string(content[:i]), "\n")
}

// npmPkgName extracts a package name from a lockfile key that may be a
// node_modules path: "node_modules/openai" -> "openai",
// "node_modules/a/node_modules/@langchain/core" -> "@langchain/core".
// The root entry ("") and anything not under node_modules yield "".
func npmPkgName(key string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return ""
	}
	return key[i+len(marker):]
}

// npmSpecName splits a yarn/pnpm "name@range" key into its package name.
// The separator is the LAST '@' at a non-zero index, so scoped packages
// survive: "@langchain/core@npm:^0.2.0" -> "@langchain/core".
func npmSpecName(spec string) string {
	spec = strings.Trim(spec, `"' `)
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return spec[:i]
	}
	return spec
}

// lowerName is the npm catalog's normalization (npm names are lowercase).
func lowerName(s string) string { return strings.ToLower(s) }
