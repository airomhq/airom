package dataset

import (
	"bytes"
	"context"
	"path"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
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

// DetectFile classifies the routed file from its header sample, name, and size.
//
// A structurally-valid CSV or JSONL is NOT enough: see signals.go. The file must
// corroborate the dataset claim through its fields, its name/path, or a
// self-describing columnar format — otherwise no finding is emitted at all.
func (d *Dataset) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	format, method, conf, ok := sniff(f.Path(), f.Header())
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

// Confidence by corroboration. Two independent signals beat one, and the
// content-derived field signal outranks the name, which a file can carry by
// coincidence.
const (
	confFields      = 0.75 // ML-shaped columns/keys: evidence about the content
	confName        = 0.65 // named/filed as a dataset
	confFormat      = 0.7  // magic-verified Parquet/Arrow
	confCorroborate = 0.85 // two or more of the above
)

// sniff decides the format, method, and confidence for a routed file, or
// reports ok=false when nothing corroborates the extension.
func sniff(p string, header []byte) (format string, method airom.DetectionMethod, conf airom.Confidence, ok bool) {
	ext := strings.ToLower(path.Ext(p))
	named := nameSignal(p)

	switch ext {
	case ".parquet", ".arrow":
		format = strings.TrimPrefix(ext, ".")
		magic := parquetMagic
		if ext == ".arrow" {
			magic = arrowMagic
		}
		if !bytes.HasPrefix(header, magic) {
			// The extension lies, or the file is truncated. Only a dataset-ish
			// name keeps it, and then only as a filename-grade claim.
			if named {
				return format, airom.MethodFilename, confName, true
			}
			return "", "", 0, false
		}
		if named {
			return format, airom.MethodBinary, confCorroborate, true
		}
		return format, airom.MethodBinary, confFormat, true

	case ".jsonl":
		fields := jsonlFields(header)
		if fields == nil { // not JSON Lines at all
			return "", "", 0, false
		}
		return textual("jsonl", fieldSignal(fields), named)

	case ".csv":
		fields := csvFields(header)
		if fields == nil { // not a delimited record
			return "", "", 0, false
		}
		return textual("csv", fieldSignal(fields), named)
	}
	return "", "", 0, false
}

// textual grades a structurally-valid CSV/JSONL by its corroborating signals.
// With neither, the file is some other program's data and we say nothing.
func textual(format string, fields, named bool) (string, airom.DetectionMethod, airom.Confidence, bool) {
	switch {
	case fields && named:
		return format, airom.MethodSourceCode, confCorroborate, true
	case fields:
		// Derived from the header row, not the path: a content claim.
		return format, airom.MethodSourceCode, confFields, true
	case named:
		return format, airom.MethodFilename, confName, true
	default:
		return "", "", 0, false
	}
}

// firstLine returns the first line of the sample with surrounding whitespace
// trimmed, without its terminator.
func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return bytes.TrimSpace(b)
}
