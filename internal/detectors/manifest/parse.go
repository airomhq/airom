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
// markers", or "name @ url") into its distribution name and a cleaned
// version. It never allocates proportional to input beyond slicing.
func parsePEP508(s string) (name, version string) {
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
	version = cleanVersion(rest)
	return name, version
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
