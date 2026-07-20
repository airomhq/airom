package airom

import "strings"

// ArtifactRisk is one structural, statically-detected property of an artifact
// that enables code execution or content injection at load time — a poisoned
// checkpoint, an unsafe deserialization surface. It is **suspicion with
// evidence, never a verdict**: the absence of risks is not a safety claim, and
// a risk is not a malware conviction. Severity is a fixed function of the risk
// ID (RiskCatalog), so it is deterministic and never judgment-at-scan-time.
type ArtifactRisk struct {
	ID         RiskID       `json:"id"`
	Severity   RiskSeverity `json:"severity"`
	Detail     []string     `json:"detail,omitempty"` // the exact symbols/keys, sorted, deduped
	Occurrence *Occurrence  `json:"occurrence,omitempty"`
}

// RiskID is a stable catalog identifier. It projects verbatim as the
// CycloneDX vulnerability `id` (a non-CVE id with a named source is legal).
type RiskID string

const (
	// RiskPickleImport is raised when a pickle GLOBAL resolves to a dangerous
	// callable (os.system, builtins.eval, subprocess.*), so unpickling the
	// checkpoint executes code.
	RiskPickleImport RiskID = "AIROM-RISK-PICKLE-IMPORT"
	// RiskKerasLambda is raised when a Keras model config declares a Lambda
	// layer, which marshals arbitrary Python executed at load time.
	RiskKerasLambda RiskID = "AIROM-RISK-KERAS-LAMBDA"
	// RiskGGUFTemplate is raised when a GGUF tokenizer.chat_template contains
	// Jinja sandbox-escape gadgets — a template-injection surface.
	RiskGGUFTemplate RiskID = "AIROM-RISK-GGUF-TEMPLATE"
	// RiskSavedModelPyFunc is raised when a TensorFlow SavedModel graph
	// contains a PyFunc-family op, which invokes arbitrary Python.
	RiskSavedModelPyFunc RiskID = "AIROM-RISK-SAVEDMODEL-PYFUNC"
)

// RiskSeverity is the deterministic severity bucket for a risk.
type RiskSeverity string

// The severity buckets, low to high. Fixed per RiskID via RiskCatalog.
const (
	RiskLow    RiskSeverity = "low"
	RiskMedium RiskSeverity = "medium"
	RiskHigh   RiskSeverity = "high"
)

// RiskMeta is the static catalog entry behind a RiskID: everything the writers
// and the policy gate need, with no per-scan judgment.
type RiskMeta struct {
	Severity    RiskSeverity
	Slug        string // stable short form for --fail-on and the SARIF rule id
	Title       string
	Description string // what the risk means; the ArtifactRisk.Detail carries the specifics
}

// RiskCatalog maps each RiskID to its fixed metadata. The single source of
// truth for severity, the policy slug, and the writer descriptions.
var RiskCatalog = map[RiskID]RiskMeta{
	RiskPickleImport: {
		Severity: RiskHigh,
		Slug:     "pickle-import",
		Title:    "Unsafe pickle import",
		Description: "A pickle GLOBAL resolves to a code-execution callable; " +
			"loading this artifact runs code before any model is produced.",
	},
	RiskKerasLambda: {
		Severity: RiskHigh,
		Slug:     "keras-lambda",
		Title:    "Keras Lambda layer",
		Description: "A Keras model config declares a Lambda layer, which " +
			"marshals arbitrary Python that executes when the model is loaded.",
	},
	RiskGGUFTemplate: {
		Severity: RiskMedium,
		Slug:     "gguf-template",
		Title:    "Unsafe GGUF chat template",
		Description: "The GGUF tokenizer.chat_template contains Jinja " +
			"sandbox-escape gadgets; rendering a prompt with it can execute code.",
	},
	RiskSavedModelPyFunc: {
		Severity: RiskMedium,
		Slug:     "savedmodel-pyfunc",
		Title:    "SavedModel Python-callback op",
		Description: "The SavedModel graph contains a PyFunc-family op, which " +
			"invokes arbitrary Python during inference.",
	},
}

// RiskByID returns the catalog entry, falling back to a low-severity unknown
// so an out-of-catalog id (e.g. a forward-compat inventory) still projects
// safely instead of panicking. The fallback slug is DERIVED from the id, so
// two distinct unknown ids never collapse to the same SARIF rule id.
func RiskByID(id RiskID) RiskMeta {
	if m, ok := RiskCatalog[id]; ok {
		return m
	}
	return RiskMeta{Severity: RiskLow, Slug: "unknown-" + unknownSlug(id), Title: string(id), Description: string(id)}
}

// unknownSlug renders an unrecognized RiskID as a stable, slug-safe token: the
// lowercased id with every run of non-[a-z0-9] characters collapsed to a dash.
func unknownSlug(id RiskID) string {
	lower := strings.ToLower(string(id))
	var b []byte
	dash := false
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b = append(b, c)
			dash = false
		} else if !dash && len(b) > 0 {
			b = append(b, '-')
			dash = true
		}
	}
	s := strings.Trim(string(b), "-")
	if s == "" {
		return "x"
	}
	return s
}

// RiskSlugToID inverts the catalog slug → id, for the --fail-on grammar.
func RiskSlugToID(slug string) (RiskID, bool) {
	for id, m := range RiskCatalog {
		if m.Slug == slug {
			return id, true
		}
	}
	return "", false
}

// RiskSeverities lists the valid severity buckets, for grammar validation.
func RiskSeverities() []RiskSeverity { return []RiskSeverity{RiskLow, RiskMedium, RiskHigh} }
