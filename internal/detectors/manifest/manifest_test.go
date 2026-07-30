package manifest

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom/detect"
	"github.com/airomhq/airom/pkg/airom/detectortest"
)

func TestRequirements(t *testing.T) {
	detectortest.Run(t, NewRequirements(), detectortest.Fixtures{Dir: "testdata/requirements"})
}

func TestInstalled(t *testing.T) {
	detectortest.Run(t, NewInstalled(), detectortest.Fixtures{Dir: "testdata/installed"})
}

func TestPackageLock(t *testing.T) {
	detectortest.Run(t, NewPackageLock(), detectortest.Fixtures{Dir: "testdata/npmlock"})
}

func TestYarnLock(t *testing.T) {
	detectortest.Run(t, NewYarnLock(), detectortest.Fixtures{Dir: "testdata/yarnlock"})
}

func TestPnpmLock(t *testing.T) {
	detectortest.Run(t, NewPnpmLock(), detectortest.Fixtures{Dir: "testdata/pnpmlock"})
}

func TestPoetryLock(t *testing.T) {
	detectortest.Run(t, NewPoetryLock(), detectortest.Fixtures{Dir: "testdata/pypilock"})
}

func TestPipfileLock(t *testing.T) {
	detectortest.Run(t, NewPipfileLock(), detectortest.Fixtures{Dir: "testdata/pipfilelock"})
}

func TestPyProject(t *testing.T) {
	detectortest.Run(t, NewPyProject(), detectortest.Fixtures{Dir: "testdata/pyproject"})
}

func TestPackageJSON(t *testing.T) {
	detectortest.Run(t, NewPackageJSON(), detectortest.Fixtures{Dir: "testdata/npm"})
}

func TestGoMod(t *testing.T) {
	detectortest.Run(t, NewGoMod(), detectortest.Fixtures{Dir: "testdata/gomod"})
}

func TestMaven(t *testing.T) {
	detectortest.Run(t, NewMaven(), detectortest.Fixtures{Dir: "testdata/maven"})
}

func TestGradle(t *testing.T) {
	detectortest.Run(t, NewGradle(), detectortest.Fixtures{Dir: "testdata/gradle"})
}

func TestCargo(t *testing.T) {
	detectortest.Run(t, NewCargo(), detectortest.Fixtures{Dir: "testdata/cargo"})
}

func TestCSProj(t *testing.T) {
	detectortest.Run(t, NewCSProj(), detectortest.Fixtures{Dir: "testdata/nuget"})
}

// TestConstructorsImplementFileDetector is a compile-time guard that every
// constructor returns a detect.FileDetector (the shape the engine's generator
// discovers and the harness requires).
func TestConstructorsImplementFileDetector(t *testing.T) {
	dets := []detect.FileDetector{
		NewRequirements(), NewPyProject(), NewPackageJSON(), NewGoMod(),
		NewMaven(), NewGradle(), NewCargo(), NewCSProj(), NewInstalled(),
		NewPackageLock(), NewYarnLock(), NewPnpmLock(), NewPoetryLock(), NewPipfileLock(),
	}
	seen := map[string]bool{}
	for _, d := range dets {
		if d.ID() == "" {
			t.Errorf("%T: empty ID", d)
		}
		if seen[d.ID()] {
			t.Errorf("duplicate detector ID %q", d.ID())
		}
		seen[d.ID()] = true
	}
}
