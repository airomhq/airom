package infra

import (
	"context"
	"strings"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Dockerfile detects AI serving infrastructure declared in a Dockerfile:
// recognized base images and AI environment variables.
type Dockerfile struct{}

// NewDockerfile constructs the Dockerfile detector.
func NewDockerfile() *Dockerfile { return &Dockerfile{} }

// ID is the stable SARIF ruleId.
func (*Dockerfile) ID() string { return "infra/dockerfile" }

// Version participates in the cache key; bump on any behavior change.
func (*Dockerfile) Version() int { return 1 }

// Selector routes Dockerfiles by basename and the *.Dockerfile convention.
func (*Dockerfile) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"Dockerfile"},
		PathGlobs: []string{"**/Dockerfile", "**/*.Dockerfile"},
		Need:      detect.NeedContent,
	}
}

// DetectFile line-scans a Dockerfile for FROM/EXPOSE/ENV signals, attributing
// ports and env keys to the most recent recognized base image.
func (d *Dockerfile) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
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
		keyword, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(keyword) {
		case "FROM":
			if tool, ok := matchImage(arg); ok && !seen[tool] {
				seen[tool] = true
				cur = newHit(tool, i+1, 0.75)
				hits = append(hits, cur)
			}
		case "EXPOSE":
			if cur != nil && cur.endpoint == "" {
				cur.endpoint = firstPort(arg)
			}
		case "ENV":
			// OLLAMA_HOST is specific enough to stand alone when no base
			// image named Ollama has matched.
			if cur == nil && strings.Contains(line, "OLLAMA_HOST") && !seen["ollama"] {
				seen["ollama"] = true
				cur = newHit("ollama", i+1, 0.7)
				hits = append(hits, cur)
			}
			if cur != nil {
				cur.addEnv(line)
			}
		}
	}

	return findings(hits), nil
}
