package project

import (
	"encoding/json"
	"io"
	"path"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// maxConfigBytes caps how much of any config file the project detectors read
// before parsing. These files hold untrusted bytes (§13); a real HuggingFace
// config, adapter config, or generation config is a few KB, so a 4 MiB gate
// keeps allocation bounded and turns a pathological input into a parse error
// (⇒ skip) rather than an OOM.
const maxConfigBytes = 4 << 20

// openAll reads a resolver file into memory under the maxConfigBytes cap. The
// Resolver honors the same ignore rules as the phase-1 walk, so a project
// detector can never open a file phase 1 could not see.
func openAll(r detect.Resolver, p string) ([]byte, error) {
	rc, err := r.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(io.LimitReader(rc, maxConfigBytes))
}

// dirNameFor is the directory basename used as a component name, guarding the
// scan-root ("." / "" / "/") case where there is no meaningful directory
// name.
func dirNameFor(dir string) string {
	b := path.Base(dir)
	if b == "." || b == "/" || b == "" {
		return "model"
	}
	return b
}

// jsonString returns the string value of a top-level JSON field, or "" when
// absent, null, or not a string. It never errors: a config with an
// unexpected shape simply yields no value.
func jsonString(obj map[string]json.RawMessage, key string) string {
	raw, ok := obj[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// jsonStrings returns the string slice of a top-level JSON field, or nil when
// absent or not an array of strings.
func jsonStrings(obj map[string]json.RawMessage, key string) []string {
	raw, ok := obj[key]
	if !ok {
		return nil
	}
	var s []string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return s
}
