package manifest

import (
	"context"
	"strings"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Gradle detects AI dependencies in Gradle build scripts (build.gradle and
// build.gradle.kts) by best-effort line scanning — a Groovy/Kotlin DSL is not
// statically resolvable, but declared coordinates are readable (decision D13).
type Gradle struct{}

// NewGradle constructs the Gradle build-script detector.
func NewGradle() *Gradle { return &Gradle{} }

// ID is the stable detector identity.
func (Gradle) ID() string { return "manifest/gradle" }

// Version participates in cache keys; bump on any behavior change.
func (Gradle) Version() int { return 1 }

// Selector routes build.gradle and build.gradle.kts files.
func (Gradle) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"build.gradle", "build.gradle.kts"},
		MaxSize:   4 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile scans each line for a Maven coordinate — either the compact
// "group:artifact:version" string or the map notation (group:/name:/version:).
func (d Gradle) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	var out []detect.Finding
	for i, line := range splitLines(content) {
		group, artifact, version, ok := gradleCoord(line)
		if !ok {
			continue
		}
		p, matched := mavenLookup(group, artifact)
		if !matched {
			continue
		}
		out = append(out, mkFinding(p, p.emitName(artifact), group, "maven", strings.TrimSpace(version), i+1))
	}
	return out, nil
}

// gradleCoord extracts a (group, artifact, version) coordinate from one line.
func gradleCoord(line string) (group, artifact, version string, ok bool) {
	// Compact "group:artifact:version" string literal.
	for _, s := range quotedStrings(line) {
		parts := strings.Split(s, ":")
		if len(parts) == 2 || len(parts) == 3 {
			group, artifact = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			if len(parts) == 3 {
				version = strings.TrimSpace(parts[2])
			}
			if group != "" && artifact != "" {
				return group, artifact, version, true
			}
		}
	}
	// Map notation: group: '…', name: '…', version: '…'.
	if strings.Contains(line, "group:") && strings.Contains(line, "name:") {
		group = valueAfter(line, "group:")
		artifact = valueAfter(line, "name:")
		version = valueAfter(line, "version:")
		if group != "" && artifact != "" {
			return group, artifact, version, true
		}
	}
	return "", "", "", false
}

// valueAfter returns the first quoted string following the key marker.
func valueAfter(line, key string) string {
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	return firstQuoted(line[i+len(key):])
}
