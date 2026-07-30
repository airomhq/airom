package manifest

import "strings"

// cleanVersion strips a version specifier down to its first concrete version
// token: "==1.2.3" -> "1.2.3", ">= 0.5" -> "0.5", "^1.0" -> "1.0",
// ">=2.0,<3.0" -> "2.0", "*" -> "". An unparseable or wildcard spec yields
// "" (unknown version, per the folding law).
func cleanVersion(s string) string {
	s = strings.TrimSpace(s)
	// Drop leading comparison/caret/tilde operators and surrounding spaces.
	s = strings.TrimLeft(s, "=<>!~^* \t")
	// Cut at the first delimiter that ends the leading version token.
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ',', ';', ' ', '\t', '#', '|', '(', ')':
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

// versionSpec splits a declared dependency specifier into a resolved version
// and a declared constraint. At most one is non-empty; both are empty when the
// spec names no version at all.
//
// bareIsExact says what an operator-less spec means in the ecosystem, which is
// not the same everywhere:
//
//	npm "4.28.4"       exactly 4.28.4          → bareIsExact
//	go.mod v1.2.3      exactly v1.2.3 (MVS)    → bareIsExact
//	Maven <version>    the named release       → bareIsExact
//	Cargo "1.0"        ^1.0, i.e. >=1.0 <2.0   → NOT exact
//	Poetry "1.40.0"    ^1.40.0                 → NOT exact
//
// Getting that wrong in either direction is a lie: calling a range exact
// invents a version, and calling an exact pin a range discards a real one.
func versionSpec(spec string, bareIsExact bool) (version, constraint string) {
	s := strings.TrimSpace(spec)
	if s == "" || s == "*" {
		return "", ""
	}
	pinned := false
	for _, op := range []string{"===", "==", "="} {
		if r, ok := strings.CutPrefix(s, op); ok {
			s, pinned = strings.TrimSpace(r), true
			break
		}
	}
	if !isPlainVersion(s) {
		return "", strings.TrimSpace(spec)
	}
	if pinned || bareIsExact {
		return s, ""
	}
	return "", strings.TrimSpace(spec)
}

// isPlainVersion reports whether s is a single concrete release token — no
// operators, wildcards, alternatives, or dist-tags. "1.40.0" and "v1.2.3" are;
// "^1.0", "1.2.x", ">=1 <2", and "latest" are not.
func isPlainVersion(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == 'v' || s[0] == 'V' {
		i = 1
	}
	if i >= len(s) || s[i] < '0' || s[i] > '9' {
		return false
	}
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '<', '>', '=', '~', '^', '*', '|', ',', ' ', '\t':
			return false
		}
	}
	// A wildcard segment is a range written without an operator.
	for _, seg := range strings.Split(s, ".") {
		if seg == "x" || seg == "X" {
			return false
		}
	}
	return true
}

// isNameByte reports whether c may appear in a package name (PEP 508 /
// crate / distribution names).
func isNameByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.' || c == '_' || c == '-':
		return true
	}
	return false
}

// parsePEP508 splits a PEP 508 requirement ("name[extras] op version ;
// markers", or "name @ url") into its distribution name and the RAW version
// specifier — operators included, so the caller can tell "==1.2.3" from
// ">=1.2.3". It never allocates proportional to input beyond slicing.
func parsePEP508(s string) (name, spec string) {
	s = strings.TrimSpace(s)
	// Strip environment markers.
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	// Strip a PEP 508 direct URL reference ("name @ https://…").
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	// Leading run of name bytes is the distribution name.
	i := 0
	for i < len(s) && isNameByte(s[i]) {
		i++
	}
	name = s[:i]
	rest := strings.TrimSpace(s[i:])
	// Skip an extras group "[extra1,extra2]".
	if strings.HasPrefix(rest, "[") {
		if j := strings.IndexByte(rest, ']'); j >= 0 {
			rest = strings.TrimSpace(rest[j+1:])
		}
	}
	return name, rest
}

// quotedStrings extracts every single- or double-quoted string literal on a
// line, in order. Used to read TOML string arrays and inline values.
func quotedStrings(line string) []string {
	var out []string
	for i := 0; i < len(line); i++ {
		q := line[i]
		if q != '"' && q != '\'' {
			continue
		}
		if j := strings.IndexByte(line[i+1:], q); j >= 0 {
			out = append(out, line[i+1:i+1+j])
			i += j + 1
		} else {
			break
		}
	}
	return out
}

// firstQuoted returns the first quoted string literal on a line, or "".
func firstQuoted(line string) string {
	if s := quotedStrings(line); len(s) > 0 {
		return s[0]
	}
	return ""
}

// splitLines splits content into lines without a trailing empty element for a
// terminal newline, preserving 1-based indexing when iterated with i+1.
func splitLines(content []byte) []string {
	return strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
}
