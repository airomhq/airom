package manifest

import (
	"context"
	"strings"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// PackageJSON detects AI dependencies declared in an npm package.json, across
// both dependencies and devDependencies.
type PackageJSON struct{}

// NewPackageJSON constructs the npm package.json detector.
func NewPackageJSON() *PackageJSON { return &PackageJSON{} }

// ID is the stable detector identity.
func (PackageJSON) ID() string { return "manifest/npm" }

// Version participates in cache keys; bump on any behavior change.
func (PackageJSON) Version() int { return 1 }

// Selector routes package.json files, needing full content.
func (PackageJSON) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"package.json"},
		MaxSize:   8 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile scans each dependency object as a flat token stream and matches
// every declared package against the npm catalog. Scanning the object's brace
// span (rather than one dependency per line) means the pretty-printed, inline,
// and fully minified layouts all resolve identically. (Phase 10 review.)
func (d PackageJSON) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}

	var out []detect.Finding
	for _, section := range []string{"dependencies", "devDependencies"} {
		for _, dep := range npmDeps(content, section) {
			p, ok := npmCatalog.lookup(strings.ToLower(dep.name))
			if !ok {
				continue
			}
			out = append(out, mkFinding(p, p.emitName(dep.name), "", "npm", cleanVersion(dep.spec), dep.line))
		}
	}
	return out, nil
}

// npmDep is one declared dependency with its 1-based line for evidence.
type npmDep struct {
	name, spec string
	line       int
}

// npmDeps extracts every (name, spec) pair from the top-level object value of
// the given key, independent of formatting. Within a JSON dependency object
// the quoted strings strictly alternate key, value, so the object's brace span
// is scanned as a flat token stream. The line is derived from the name's byte
// offset so single-line and minified objects still report a real line.
func npmDeps(content []byte, section string) []npmDep {
	s := string(content)
	key := `"` + section + `"`

	// Find the occurrence of the key that is actually followed by ": {" — a
	// decoy inside some earlier value (e.g. a script string) is skipped.
	open := -1
	for from := 0; ; {
		ki := strings.Index(s[from:], key)
		if ki < 0 {
			return nil
		}
		ki += from
		p := skipJSONSpace(s, ki+len(key))
		if p < len(s) && s[p] == ':' {
			if p = skipJSONSpace(s, p+1); p < len(s) && s[p] == '{' {
				open = p
				break
			}
		}
		from = ki + len(key)
	}

	// Find the matching close brace, ignoring braces inside quoted strings.
	depth, end := 0, -1
	for i := open; i < len(s) && end < 0; i++ {
		switch s[i] {
		case '"':
			if j := strings.IndexByte(s[i+1:], '"'); j >= 0 {
				i += j + 1
			} else {
				i = len(s)
			}
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				end = i
			}
		}
	}
	if end < 0 {
		end = len(s)
	}

	// Collect quoted tokens (with offsets) within the object, then pair them.
	type tok struct {
		val string
		off int
	}
	var toks []tok
	for i := open + 1; i < end; i++ {
		if s[i] != '"' {
			continue
		}
		j := strings.IndexByte(s[i+1:], '"')
		if j < 0 {
			break
		}
		toks = append(toks, tok{s[i+1 : i+1+j], i})
		i += j + 1
	}
	out := make([]npmDep, 0, len(toks)/2)
	for i := 0; i+1 < len(toks); i += 2 {
		out = append(out, npmDep{
			name: toks[i].val,
			spec: toks[i+1].val,
			line: 1 + strings.Count(s[:toks[i].off], "\n"),
		})
	}
	return out
}

// skipJSONSpace advances past JSON insignificant whitespace.
func skipJSONSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}
