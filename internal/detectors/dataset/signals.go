package dataset

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"path"
	"strings"
)

// Corroboration: why a .csv is not a dataset.
//
// "It parses as CSV" is not evidence of an AI dataset. A GRIB2 weather table, a
// MAC-address OUI registry, an OpenTelemetry metrics export and a UI color
// table are all well-formed CSVs with two or more columns, and extension-only
// detection called every one of them a dataset at 0.6 — drowning real findings
// on any general-purpose tree.
//
// So a routed file must corroborate the claim with something beyond its
// extension. Three signals, in descending strength:
//
//  1. FIELDS  — the column/key names carry an ML shape ({"prompt","completion"},
//     `text,label`). This is the honest one: it is evidence about the content.
//  2. NAME    — the file is named or filed like a dataset (data/, datasets/,
//     train.jsonl, test.csv).
//  3. FORMAT  — magic-verified Parquet/Arrow: columnar formats that exist to
//     carry datasets.
//
// No signal, no finding. That is the whole fix.

// strongFields alone identify an ML dataset: outside of one, a column named
// "completion" or "rejected" has no ordinary meaning.
var strongFields = map[string]bool{
	"prompt": true, "completion": true, "instruction": true,
	"chosen": true, "rejected": true, "messages": true,
	"conversations": true, "embedding": true, "embeddings": true,
}

// moderateFields are ML-shaped but individually ordinary, so two are required.
// `text,label` is a classification set; a lone "input" column is not evidence.
var moderateFields = map[string]bool{
	"text": true, "label": true, "labels": true, "target": true,
	"question": true, "answer": true, "context": true, "document": true,
	"query": true, "passage": true, "response": true, "input": true,
	"output": true, "feature": true, "features": true, "tokens": true,
	"conversation": true, "summary": true,
}

// datasetDirs are path segments whose contents are datasets by convention.
var datasetDirs = map[string]bool{
	"data": true, "dataset": true, "datasets": true,
	"corpus": true, "corpora": true, "training": true,
}

// datasetNames are conventional dataset basenames (sans extension).
//
// Matched EXACTLY, never as a prefix: "test-linux.csv" and
// "test-dependency-mapper.csv" are not datasets, and a `strings.HasPrefix`
// check would swallow both.
var datasetNames = map[string]bool{
	"train": true, "test": true, "valid": true, "validation": true,
	"eval": true, "dev": true, "dataset": true, "corpus": true,
	"training": true, "holdout": true,
}

// fieldSignal reports whether the column/key names look like an ML dataset.
func fieldSignal(fields []string) bool {
	strong, moderate := 0, 0
	for _, f := range fields {
		switch k := normalizeField(f); {
		case strongFields[k]:
			strong++
		case moderateFields[k]:
			moderate++
		}
	}
	return strong >= 1 || moderate >= 2
}

// normalizeField lowercases and strips the punctuation column names pick up
// ("Input_Text" -> "inputtext"; "chosen " -> "chosen").
func normalizeField(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer("_", "", "-", "", " ", "", ".", "").Replace(s)
}

// nameSignal reports whether the path files or names the file as a dataset.
func nameSignal(p string) bool {
	slash := strings.ToLower(path.Clean(p))
	for _, seg := range strings.Split(path.Dir(slash), "/") {
		if datasetDirs[seg] {
			return true
		}
	}
	base := path.Base(slash)
	return datasetNames[strings.TrimSuffix(base, path.Ext(base))]
}

// csvFields returns the header row's field names, or nil.
func csvFields(header []byte) []string {
	line := firstLine(header)
	if len(line) == 0 {
		return nil
	}
	r := csv.NewReader(bytes.NewReader(line))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	rec, err := r.Read()
	if err != nil || len(rec) < 2 {
		return nil
	}
	return rec
}

// jsonlFields returns the first record's keys, or nil.
//
// Key order is irrelevant here — only membership is tested — so the map's
// nondeterministic range order cannot reach the output (P7).
func jsonlFields(header []byte) []string {
	line := firstLine(header)
	if len(line) == 0 || line[0] != '{' {
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(line, &obj) != nil {
		return nil
	}
	out := make([]string, 0, len(obj))
	for k := range obj {
		out = append(out, k)
	}
	return out
}
