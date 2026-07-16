package k8ssource

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Roro1727/airom/internal/source"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const deploymentYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  template:
    spec:
      initContainers:
        - name: init
          image: busybox:1.36
      containers:
        - name: nginx
          image: nginx:1.25
`

const podYAML = `
apiVersion: v1
kind: Pod
metadata:
  name: cache
spec:
  containers:
    - name: nginx
      image: nginx:1.25
    - name: redis
      image: redis:7
`

func TestImagesDeduped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, dir, "deploy.yaml", deploymentYAML)
	write(t, dir, "pod.yml", podYAML)

	s, err := New(Options{ManifestsDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	got := s.Images()
	want := []string{"busybox:1.36", "nginx:1.25", "redis:7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Images() = %v, want %v", got, want)
	}
	if u := s.WalkUnknowns(); len(u) != 0 {
		t.Errorf("unexpected unknowns: %v", u)
	}
}

func TestAISignals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, dir, "ai.yaml", `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm
spec:
  template:
    spec:
      containers:
        - name: server
          image: ollama/ollama:latest
          env:
            - name: OLLAMA_HOST
              value: "http://ollama:11434"
            - name: MODEL_ID
              value: "llama3"
            - name: HF_TOKEN
              value: "hf_secret"
            - name: UNRELATED
              value: "ignored"
`)

	s, err := New(Options{ManifestsDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	details := s.Details()
	if len(details) != 1 {
		t.Fatalf("Details() len = %d, want 1", len(details))
	}
	sig := details[0].Signals
	want := map[string]string{
		"OLLAMA_HOST": "http://ollama:11434",
		"MODEL_ID":    "llama3",
		"HF_TOKEN":    "hf_secret",
	}
	if !reflect.DeepEqual(sig, want) {
		t.Errorf("Signals = %v, want %v", sig, want)
	}
	if wl := details[0].Workloads; len(wl) != 1 || wl[0] != "Deployment/llm" {
		t.Errorf("Workloads = %v, want [Deployment/llm]", wl)
	}
}

func TestCronJobAndMultiDoc(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, dir, "multi.yaml", `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: task
              image: alpine:3
---
apiVersion: batch/v1
kind: Job
metadata:
  name: once
spec:
  template:
    spec:
      containers:
        - name: run
          image: curlimages/curl:8
`)

	s, err := New(Options{ManifestsDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	got := s.Images()
	want := []string{"alpine:3", "curlimages/curl:8"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Images() = %v, want %v", got, want)
	}
}

func TestUnrecognizedKindSkipped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A CRD that happens to carry a pod-template-like structure must be ignored.
	write(t, dir, "crd.yaml", `
apiVersion: example.com/v1
kind: FancyResource
metadata:
  name: x
spec:
  template:
    spec:
      containers:
        - name: c
          image: should-not-appear:1
`)
	s, err := New(Options{ManifestsDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()
	if got := s.Images(); len(got) != 0 {
		t.Errorf("Images() = %v, want empty for unrecognized kind", got)
	}
}

func TestMalformedDocRecorded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, dir, "good.yaml", podYAML)
	write(t, dir, "bad.yaml", "kind: Pod\nspec:\n  containers:\n  - image: [unterminated\n")

	s, err := New(Options{ManifestsDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	// The good file still contributes its images.
	if got := s.Images(); len(got) == 0 {
		t.Errorf("expected images from the good file despite the malformed one")
	}
	// The malformed file is surfaced as an Unknown (P6), never silently dropped.
	found := false
	for _, u := range s.WalkUnknowns() {
		if strings.Contains(u.Path, "bad.yaml") {
			found = true
		}
	}
	if !found {
		t.Errorf("malformed doc not recorded in unknowns: %v", s.WalkUnknowns())
	}
}

func TestLiveModeError(t *testing.T) {
	t.Parallel()
	_, err := New(Options{})
	if err == nil {
		t.Fatal("New(no manifests dir) = nil error, want live-cluster error")
	}
	if !strings.Contains(err.Error(), "--manifests") {
		t.Errorf("error = %q, want it to direct to --manifests", err.Error())
	}
}

func TestContractBasics(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, dir, "pod.yaml", podYAML)
	s, err := New(Options{ManifestsDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.Kind() != source.KindK8s {
		t.Errorf("Kind = %q, want k8s", s.Kind())
	}
	if info := s.Info(); info.Kind != source.KindK8s {
		t.Errorf("Info.Kind = %q, want k8s", info.Kind)
	}

	// Walk yields no entries (the app fans out via Images()).
	n := 0
	if err := s.Walk(context.Background(), func(source.Entry) error { n++; return nil }); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if n != 0 {
		t.Errorf("Walk yielded %d entries, want 0", n)
	}

	// Resolver is a no-op.
	refs, err := s.Resolver().FilesByGlob(context.Background(), "**/*")
	if err != nil || len(refs) != 0 {
		t.Errorf("FilesByGlob = %v, %v; want empty, nil", refs, err)
	}
	if _, err := s.Resolver().Open("anything"); err == nil {
		t.Errorf("Resolver.Open = nil error, want error")
	}
}
