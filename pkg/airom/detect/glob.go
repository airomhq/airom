package detect

import (
	"path"
	"strings"
)

// Match reports whether a slash-separated relative path matches a selector
// glob. Supported syntax (a portable doublestar subset, stdlib-only):
//
//   - `**` as a WHOLE segment matches zero or more segments
//   - within a segment: `*`, `?`, and `[…]` classes per path.Match
//   - a trailing `/**` matches everything under the prefix
//
// Invalid patterns match nothing (selector globs are validated at catalog
// build time via ValidateGlob).
func Match(pattern, p string) bool {
	return matchSegs(strings.Split(pattern, "/"), strings.Split(p, "/"))
}

// ValidateGlob reports whether every segment of pattern is a valid
// path.Match pattern.
func ValidateGlob(pattern string) bool {
	for _, seg := range strings.Split(pattern, "/") {
		if seg == "**" {
			continue
		}
		if _, err := path.Match(seg, "probe"); err != nil {
			return false
		}
	}
	return true
}

func matchSegs(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// Collapse consecutive ** and try every suffix split.
			for len(pat) > 0 && pat[0] == "**" {
				pat = pat[1:]
			}
			if len(pat) == 0 {
				return true // trailing ** matches everything (incl. nothing)
			}
			for i := 0; i <= len(segs); i++ {
				if matchSegs(pat, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], segs[0])
		if err != nil || !ok {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}
