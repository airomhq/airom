package dataset

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"path"
	"strings"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// Magic prefixes for the self-describing binary dataset formats.
var (
	parquetMagic = []byte("PAR1")
	arrowMagic   = []byte("ARROW1")
)

// Dataset detects dataset files by extension plus a header-only format
// signature: CSV and JSONL by structural sniffing, Parquet and Arrow by
// magic bytes.
type Dataset struct{}

// NewDataset constructs the dataset-file detector.
func NewDataset() *Dataset { return &Dataset{} }

// ID is the stable SARIF ruleId.
func (*Dataset) ID() string { return "dataset/file" }

// Version participates in the cache key; bump on any behavior change.
func (*Dataset) Version() int { return 1 }

// Selector routes the four dataset extensions; only the header is needed.
func (*Dataset) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".csv", ".jsonl", ".parquet", ".arrow"},
		Need:       detect.NeedHeader,
	}
}

// DetectFile classifies the routed file from its header sample and size.
func (d *Dataset) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	ext := strings.ToLower(path.Ext(f.Path()))
	format, method, conf, ok := sniff(ext, f.Header())
	if !ok {
		return nil, nil
	}
	return []detect.Finding{{
		Claim: detect.ComponentClaim{
			Kind: airom.KindDataset,
			Name: f.Base(),
			Data: &detect.DataClaim{Format: format, SizeBytes: f.Ref().Size},
		},
		Occurrence: airom.Occurrence{
			Method:     method,
			Confidence: conf,
		},
	}}, nil
}

// sniff decides the format, detection method, and confidence for a header
// under a known dataset extension. ok is false when the content contradicts
// the extension (kept honest to avoid false positives).
func sniff(ext string, header []byte) (format string, method airom.DetectionMethod, conf airom.Confidence, ok bool) {
	switch ext {
	case ".parquet":
		if bytes.HasPrefix(header, parquetMagic) {
			return "parquet", airom.MethodBinary, 0.8, true
		}
		return "parquet", airom.MethodFilename, 0.6, true
	case ".arrow":
		if bytes.HasPrefix(header, arrowMagic) {
			return "arrow", airom.MethodBinary, 0.8, true
		}
		return "arrow", airom.MethodFilename, 0.6, true
	case ".jsonl":
		if looksJSONL(header) {
			return "jsonl", airom.MethodFilename, 0.6, true
		}
		return "", "", 0, false
	case ".csv":
		if looksCSV(header) {
			return "csv", airom.MethodFilename, 0.6, true
		}
		return "", "", 0, false
	}
	return "", "", 0, false
}

// looksJSONL reports whether the first non-empty line is a JSON object — the
// defining shape of a JSON Lines record.
func looksJSONL(header []byte) bool {
	line := firstLine(header)
	if len(line) == 0 || line[0] != '{' {
		return false
	}
	var obj map[string]json.RawMessage
	return json.Unmarshal(line, &obj) == nil
}

// looksCSV reports whether the first line parses as a delimited record with
// at least two fields.
func looksCSV(header []byte) bool {
	line := firstLine(header)
	if len(line) == 0 {
		return false
	}
	r := csv.NewReader(bytes.NewReader(line))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	rec, err := r.Read()
	return err == nil && len(rec) >= 2
}

// firstLine returns the first line of the sample with surrounding whitespace
// trimmed, without its terminator.
func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return bytes.TrimSpace(b)
}
