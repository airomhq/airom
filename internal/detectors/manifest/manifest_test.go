package manifest

import (
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detect"
	"github.com/Roro1727/airom/pkg/airom/detectortest"
)

func TestRequirements(t *testing.T) {
	detectortest.Run(t, NewRequirements(), detectortest.Fixtures{Dir: "testdata/requirements"})
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
		NewMaven(), NewGradle(), NewCargo(), NewCSProj(),
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
