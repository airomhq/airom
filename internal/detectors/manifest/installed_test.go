package manifest

import "testing"

func TestIsInstalledMetadataDir(t *testing.T) {
	cases := []struct {
		dir  string
		want bool
	}{
		{"openai-1.40.0.dist-info", true},
		{"site-packages/openai-1.40.0.dist-info", true},
		{"chromadb.egg-info", true},
		{"/usr/lib/python3.12/site-packages/langchain-0.2.1.dist-info", true},
		// Suffix, not substring: a directory merely containing the words is
		// not an install root.
		{"dist-info", false},
		{"my.dist-info.backup", false},
		{"docs", false},
		{"", false},
		{".", false},
		{"/", false},
	}
	for _, c := range cases {
		if got := isInstalledMetadataDir(c.dir); got != c.want {
			t.Errorf("isInstalledMetadataDir(%q) = %v, want %v", c.dir, got, c.want)
		}
	}
}

func TestParseMetadataHeaders(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantName    string
		wantVersion string
		wantLine    int
	}{
		{
			name:        "plain",
			in:          "Metadata-Version: 2.1\nName: openai\nVersion: 1.40.0\n",
			wantName:    "openai",
			wantVersion: "1.40.0",
			wantLine:    2,
		},
		{
			name: "description cannot overwrite the headers",
			in: "Name: openai\nVersion: 1.40.0\n\n" +
				"# README\nName: evil\nVersion: 99.0.0\n",
			wantName:    "openai",
			wantVersion: "1.40.0",
			wantLine:    1,
		},
		{
			// Without the blank-line stop, a package whose Version header is
			// absent would pick one up out of its own README.
			name:        "no version, description not mined for one",
			in:          "Name: openai\n\nInstall with `pip install openai`.\nVersion: 99.0.0\n",
			wantName:    "openai",
			wantVersion: "",
			wantLine:    1,
		},
		{
			name:        "folded continuation is not a header",
			in:          "Summary: long\n Name: nope\n\tVersion: nope\nName: torch\nVersion: 2.3.0\n",
			wantName:    "torch",
			wantVersion: "2.3.0",
			wantLine:    4,
		},
		{
			name:        "header names are case-insensitive per RFC 822",
			in:          "name: openai\nVERSION: 1.40.0\n",
			wantName:    "openai",
			wantVersion: "1.40.0",
			wantLine:    1,
		},
		{
			name:        "CRLF",
			in:          "Metadata-Version: 2.1\r\nName: openai\r\nVersion: 1.40.0\r\n\r\nbody\r\n",
			wantName:    "openai",
			wantVersion: "1.40.0",
			wantLine:    2,
		},
		{
			// A duplicate header is malformed; the first one is the identity
			// the file leads with, so a late line cannot rewrite it.
			name:        "first header wins",
			in:          "Name: openai\nName: anthropic\nVersion: 1.40.0\nVersion: 0.1.0\n",
			wantName:    "openai",
			wantVersion: "1.40.0",
			wantLine:    1,
		},
		{
			name:        "empty",
			in:          "",
			wantName:    "",
			wantVersion: "",
			wantLine:    0,
		},
		{
			name:        "leading blank line ends headers immediately",
			in:          "\nName: openai\nVersion: 1.40.0\n",
			wantName:    "",
			wantVersion: "",
			wantLine:    0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name, version, line := parseMetadataHeaders([]byte(c.in))
			if name != c.wantName || version != c.wantVersion || line != c.wantLine {
				t.Errorf("parseMetadataHeaders() = (%q, %q, %d), want (%q, %q, %d)",
					name, version, line, c.wantName, c.wantVersion, c.wantLine)
			}
		})
	}
}
