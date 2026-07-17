package infra

import (
	"context"
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// fileDetector is the shared shape of the infra file detectors.
type fileDetector interface {
	DetectFile(context.Context, *detect.File) ([]detect.Finding, error)
}

func runInfra(t *testing.T, det fileDetector, path, content string) []detect.Finding {
	t.Helper()
	f := detect.NewFile(
		detect.FileRef{Path: path, Size: int64(len(content))},
		[]byte(content),
		detect.FileProviders{Content: func() ([]byte, bool, error) { return []byte(content), false, nil }},
	)
	got, err := det.DetectFile(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// assertNoLeak checks the single AI finding did not absorb a later unrelated
// service's endpoint or env keys.
func assertNoLeak(t *testing.T, got []detect.Finding, wantTool string) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("want exactly one finding (%s), got %d: %+v", wantTool, len(got), got)
	}
	f := got[0]
	if f.Claim.Name != wantTool {
		t.Errorf("finding name = %q, want %q", f.Claim.Name, wantTool)
	}
	if f.Claim.Infra != nil && f.Claim.Infra.Endpoint != "" {
		t.Errorf("%s absorbed an unrelated service's endpoint %q", wantTool, f.Claim.Infra.Endpoint)
	}
	if v, ok := f.Occurrence.Fields["env"]; ok {
		t.Errorf("%s absorbed an unrelated service's env %q", wantTool, v)
	}
}

// TestComposeNoCrossServiceLeak: an unrelated service following an AI service
// must not have its port/env folded onto the AI service. (Phase 10 review.)
func TestComposeNoCrossServiceLeak(t *testing.T) {
	content := "services:\n" +
		"  ollama:\n" +
		"    image: ollama/ollama\n" +
		"  postgres:\n" +
		"    image: postgres:16\n" +
		"    ports:\n" +
		"      - \"5432:5432\"\n" +
		"    environment:\n" +
		"      - MODEL_ID=foo\n"
	assertNoLeak(t, runInfra(t, NewCompose(), "docker-compose.yml", content), "ollama")
}

// TestDockerfileNoCrossStageLeak: a later build stage's EXPOSE/ENV must not be
// attributed to an earlier recognized AI base image. (Phase 10 review.)
func TestDockerfileNoCrossStageLeak(t *testing.T) {
	content := "FROM ollama/ollama AS base\n" +
		"FROM python:3.11\n" +
		"EXPOSE 5432\n" +
		"ENV MODEL_ID=foo\n"
	assertNoLeak(t, runInfra(t, NewDockerfile(), "Dockerfile", content), "ollama")
}
