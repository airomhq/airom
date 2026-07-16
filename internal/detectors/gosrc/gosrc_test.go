package gosrc

import (
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detectortest"
)

func TestGoSource(t *testing.T) {
	detectortest.Run(t, NewGoSource(), detectortest.Fixtures{Dir: "testdata"})
}
