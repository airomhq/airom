package manifest

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/airomhq/airom/pkg/airom/detect"
)

// TestLockfileDeterminism pins P7 for the lockfile detectors specifically.
//
// The golden harness cannot do this job here: it canonicalizes findings before
// comparing, sorting them by line, which hides any ordering the detector itself
// leaves to chance. Every lockfile parser in this package ranges over a JSON or
// YAML map, and Go randomizes that order per run, so the raw return value is
// exactly what needs checking — repeatedly, since a one-in-N ordering bug
// passes a single comparison most of the time.
func TestLockfileDeterminism(t *testing.T) {
	cases := []struct {
		det  detect.FileDetector
		path string
	}{
		{NewPackageLock(), "testdata/npmlock/package-lock.json"},
		{NewPackageLock(), "testdata/npmlock/npm-shrinkwrap.json"},
		{NewPipfileLock(), "testdata/pipfilelock/Pipfile.lock"},
		{NewYarnLock(), "testdata/yarnlock/yarn.lock"},
		{NewPnpmLock(), "testdata/pnpmlock/pnpm-lock.yaml"},
		{NewPoetryLock(), "testdata/pypilock/poetry.lock"},
	}
	for _, c := range cases {
		t.Run(filepath.Base(c.path)+"/"+c.det.ID(), func(t *testing.T) {
			data, err := os.ReadFile(c.path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			run := func() []detect.Finding {
				f := detect.NewFile(
					detect.FileRef{Path: c.path, Size: int64(len(data))},
					data,
					detect.FileProviders{
						Content: func() ([]byte, bool, error) { return data, false, nil },
					},
				)
				got, err := c.det.DetectFile(context.Background(), f)
				if err != nil {
					t.Fatalf("DetectFile: %v", err)
				}
				return got
			}
			want := run()
			if len(want) == 0 {
				t.Fatal("fixture produced no findings — the test would prove nothing")
			}
			for i := 0; i < 50; i++ {
				if got := run(); !reflect.DeepEqual(got, want) {
					t.Fatalf("run %d differs from run 0 — map iteration order reaches the output\n got: %+v\nwant: %+v", i+1, got, want)
				}
			}
		})
	}
}

// TestPackageLockDedupesByNameAndVersion pins the dedupe rule: the same
// name@version resolved at several paths is one component, while the same name
// at two versions is two.
func TestPackageLockDedupesByNameAndVersion(t *testing.T) {
	data, err := os.ReadFile("testdata/npmlock/package-lock.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	f := detect.NewFile(
		detect.FileRef{Path: "package-lock.json", Size: int64(len(data))},
		data,
		detect.FileProviders{Content: func() ([]byte, bool, error) { return data, false, nil }},
	)
	got, err := NewPackageLock().DetectFile(context.Background(), f)
	if err != nil {
		t.Fatalf("DetectFile: %v", err)
	}

	versions := map[string][]string{}
	for _, fn := range got {
		versions[fn.Claim.Name] = append(versions[fn.Claim.Name], fn.Claim.Version)
	}
	// openai is listed three times: twice at 4.28.4 (root and a nested copy)
	// and once at 3.3.0 under a legacy tool.
	if want := []string{"3.3.0", "4.28.4"}; !reflect.DeepEqual(versions["openai"], want) {
		t.Errorf("openai versions = %v, want %v (duplicates collapsed, distinct versions kept)", versions["openai"], want)
	}
	if len(versions["express"]) != 0 {
		t.Errorf("express reported %v — a non-AI package must not reach the AIBOM", versions["express"])
	}
}
