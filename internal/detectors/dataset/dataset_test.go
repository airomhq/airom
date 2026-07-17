package dataset

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom/detectortest"
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

// TestNoiseIsNotADataset locks the corroboration gate against the real
// false positives that swamped a general-purpose scan: a well-formed CSV or
// JSONL is not evidence of an AI dataset. Each of these parses perfectly and
// was previously reported at 0.6.
func TestNoiseIsNotADataset(t *testing.T) {
	noise := []struct {
		name, why, content string
	}{
		{
			"grib2_table_4_2_0_0.csv", "a GRIB2 weather parameter table",
			"discipline,category,number,parameter,units,abbrev\n0,0,0,Temperature,K,TMP\n",
		},
		{
			"oui.csv", "a MAC-address OUI registry",
			"oui,organization,address\n00:00:0C,Cisco Systems Inc,170 West Tasman Dr\n",
		},
		{
			"open-telemetry-metrics.2026-07-17.csv", "an OpenTelemetry metrics export",
			"timestamp,metric,value,unit,host\n2026-07-17T08:30:54Z,process.cpu.time,12.4,s,build-01\n",
		},
		{
			"agent-a011eb9a45fe1d5a9.jsonl", "an agent session transcript",
			`{"type":"user","uuid":"a011eb9a","timestamp":"2026-07-17T08:30:54Z","sessionId":"s-1"}` + "\n",
		},
		{
			"colors.csv", "a UI color table",
			"name,hex,rgb\nslate,#64748b,\"100,116,139\"\n",
		},
		{
			"history.csv", "a shell history export",
			"id,command,exit\n1,ls -la,0\n",
		},
	}
	for _, n := range noise {
		if _, _, _, ok := sniff(n.name, []byte(n.content)); ok {
			t.Errorf("%s (%s) was reported as a dataset; it parses as CSV/JSONL but "+
				"carries no ML shape, no dataset name, and no columnar format", n.name, n.why)
		}
	}
}

// TestCorroboratedFilesAreStillDatasets: the gate must not silence real data.
func TestCorroboratedFilesAreStillDatasets(t *testing.T) {
	corroborated := []struct {
		name, content string
		wantMin       float64
	}{
		{"anything.jsonl", `{"prompt":"hi","completion":"hello"}` + "\n", 0.75},     // strong fields
		{"reviews.csv", "id,text,label\n1,great,positive\n", 0.75},                  // two moderate fields
		{"data/records.csv", "a,b\n1,2\n", 0.65},                                    // filed under data/
		{"train.jsonl", `{"foo":"bar","baz":1}` + "\n", 0.65},                       // named train
		{"squad.jsonl", `{"question":"q","answer":"a","context":"c"}` + "\n", 0.75}, // SQuAD shape
		{"prefs.jsonl", `{"chosen":"a","rejected":"b"}` + "\n", 0.75},               // preference data
	}
	for _, r := range corroborated {
		_, _, conf, ok := sniff(r.name, []byte(r.content))
		if !ok {
			t.Errorf("%s: corroborated dataset was rejected", r.name)
			continue
		}
		if float64(conf) < r.wantMin {
			t.Errorf("%s: confidence %.2f, want >= %.2f", r.name, conf, r.wantMin)
		}
	}
}

// A dataset-ish NAME must match exactly, never as a prefix: "test-linux.csv"
// is not a test split.
func TestDatasetNameIsNotAPrefixMatch(t *testing.T) {
	for _, n := range []string{"test-linux.csv", "test-dependency-mapper.csv", "training-guide.csv"} {
		if _, _, _, ok := sniff(n, []byte("a,b\n1,2\n")); ok {
			t.Errorf("%s: matched a dataset name by prefix; require an exact basename", n)
		}
	}
}
