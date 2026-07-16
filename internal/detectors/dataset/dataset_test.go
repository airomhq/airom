package dataset

import (
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detectortest"
)

func TestDataset(t *testing.T) {
	detectortest.Run(t, NewDataset(), detectortest.Fixtures{Dir: "testdata"})
}

// FuzzSniff feeds arbitrary bytes under each known extension: the sniffer
// eats untrusted headers and must never panic.
func FuzzSniff(f *testing.F) {
	f.Add(".csv", []byte("a,b,c\n1,2,3"))
	f.Add(".jsonl", []byte("{\"a\":1}\n"))
	f.Add(".parquet", []byte("PAR1\x00\x00PAR1"))
	f.Add(".arrow", []byte("ARROW1\x00\x00"))
	f.Add(".csv", []byte{})
	f.Fuzz(func(_ *testing.T, ext string, header []byte) {
		_, _, _, _ = sniff(ext, header)
	})
}
