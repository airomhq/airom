package infra

import (
	"context"
	"strings"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Compose detects AI serving services declared in a docker-compose file.
type Compose struct{}

// NewCompose constructs the docker-compose detector.
func NewCompose() *Compose { return &Compose{} }

// ID is the stable SARIF ruleId.
func (*Compose) ID() string { return "infra/compose" }

// Version participates in the cache key; bump on any behavior change.
func (*Compose) Version() int { return 1 }

// Selector routes the recognized compose filenames.
func (*Compose) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{
			"docker-compose.yml",
			"docker-compose.yaml",
			"compose.yml",
			"compose.yaml",
		},
		Need: detect.NeedContent,
	}
}

// DetectFile line-scans a compose file, attributing ports and env keys to the
// most recent recognized service image. This is deliberately structural line
// matching, not a full YAML parse.
func (c *Compose) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}

	var hits []*hit
	seen := map[string]bool{}
	var cur *hit

	for i, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ref, ok := composeImage(line); ok {
			// Any image line opens a new service: stop attributing ports/env to
			// the prior service, whether or not this image is a recognized AI
			// one. Otherwise an unrelated later service's port/env leaks onto an
			// earlier AI hit. (Phase 10 review, detectors finding.)
			cur = nil
			if tool, ok := matchImage(ref); ok && !seen[tool] {
				seen[tool] = true
				cur = newHit(tool, i+1, 0.75)
				hits = append(hits, cur)
			}
			continue
		}
		if cur == nil {
			continue
		}
		if p := composePort(line); p != "" {
			if cur.endpoint == "" {
				cur.endpoint = p
			}
			continue
		}
		cur.addEnv(line)
	}

	return findings(hits), nil
}

// composeImage returns the value of an `image:` key, if the line is one.
func composeImage(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, "image:")
	if !ok {
		return "", false
	}
	return strings.Trim(strings.TrimSpace(rest), `"'`), true
}

// composePort extracts the host port from a ports list item such as
// `- "11434:11434"` or `- 8000:8000/tcp`. Only entries whose value begins
// with a digit are treated as ports, so image and env lines never match.
func composePort(line string) string {
	item, ok := strings.CutPrefix(line, "-")
	if !ok {
		return ""
	}
	item = strings.Trim(strings.TrimSpace(item), `"'`)
	if item == "" || item[0] < '0' || item[0] > '9' {
		return ""
	}
	host, _, _ := strings.Cut(item, ":")
	return digitsBefore(host, '/')
}
