// Package airom is the canonical AIROM domain model (ARCHITECTURE.md §5):
// the component graph every writer projects and every detector's claims
// assemble into. It is the stable, stdlib-only public SDK surface —
// semver-guarded, importable by third-party tools without dragging any
// AIROM internals (§4, lint-enforced).
package airom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// ID is the stable component identity: "airom:" + hex(sha256(CanonicalKey))[:16].
// It seeds bom-ref (CycloneDX), spdxId (SPDX), and partialFingerprints
// (SARIF). IDs are minted exclusively by the assembler (invariant P4) —
// detectors never construct them.
type ID string

// ComponentKind classifies a component (§5). Kinds are deliberately
// AI-native: a hosted model reference and a local weights file are different
// things with different facets and different identity rules.
type ComponentKind string

// The thirteen component kinds.
const (
	KindHostedLLM      ComponentKind = "hosted-llm"       // API model ref: gpt-4.1, claude-*
	KindLocalModelFile ComponentKind = "local-model-file" // weights on disk / in image
	KindEmbeddingModel ComponentKind = "embedding-model"  // hosted or local, embedding task
	KindFramework      ComponentKind = "framework"        // langchain, transformers, vllm…
	KindLibrary        ComponentKind = "library"          // SDKs: openai, anthropic, google-genai
	KindVectorDB       ComponentKind = "vector-db"
	KindPrompt         ComponentKind = "prompt"
	KindDataset        ComponentKind = "dataset"
	KindAIConfig       ComponentKind = "ai-config" // unbound generation params (§9.5)
	KindInfra          ComponentKind = "infra"     // serving infra: ollama, vllm, tgi…
	KindService        ComponentKind = "service"   // remote endpoint: azure deployment, bedrock
	KindRAGPipeline    ComponentKind = "rag-pipeline"
	KindApplication    ComponentKind = "application" // the scan root
)

// DetectionMethod aligns 1:1 with the CycloneDX evidence technique enum
// (§5), so the CycloneDX writer is a cast, not a mapping table.
type DetectionMethod string

// The detection methods.
const (
	MethodSourceCode  DetectionMethod = "source-code-analysis"
	MethodAST         DetectionMethod = "ast-fingerprint"
	MethodManifest    DetectionMethod = "manifest-analysis"
	MethodBinary      DetectionMethod = "binary-analysis" // magic bytes + header parse
	MethodHash        DetectionMethod = "hash-comparison" // known-weights digest match
	MethodConfig      DetectionMethod = "config-analysis" // yaml/toml/env/dockerfile
	MethodFilename    DetectionMethod = "filename"
	MethodAttestation DetectionMethod = "attestation" // v2: sigstore/in-toto verified
)

// Confidence is a calibrated belief in [0,1]. Detectors emit per-sighting
// confidence; component-level confidence is computed by the assembler's
// grouped noisy-OR (§9.3) and clamps at 0.99 — only hash-comparison against
// known weights (or a verified attestation, v2) may assert 1.0.
type Confidence float64

// Band buckets a confidence for table output and --min-confidence UX.
func (c Confidence) Band() string {
	switch {
	case c >= 0.9:
		return "high"
	case c >= 0.6:
		return "medium"
	default:
		return "low"
	}
}

// ── Tri-state optionals: the SPDX NOASSERTION discipline (§5) ──────────────
//
// Confined to the fields SPDX/CycloneDX actually need it for; not pervasive.
// JSON forms: Absent is omitted (omitzero), Unknown is null, Known is the
// value — so the native format distinguishes "does not apply" from
// "applies but undetermined" losslessly.

// Presence is the tri-state discriminator.
type Presence uint8

// The three presence states. PresenceAbsent is the zero value: a field
// that does not apply is simply never set.
const (
	PresenceAbsent  Presence = iota // does not apply → omitted everywhere
	PresenceUnknown                 // applies but undetermined → SPDX NOASSERTION
	PresenceKnown
)

var nullJSON = []byte("null")

// OptString is a tri-state string.
type OptString struct {
	P Presence
	V string
}

// KnownString returns a Known OptString.
func KnownString(v string) OptString { return OptString{P: PresenceKnown, V: v} }

// UnknownString returns an Unknown OptString (SPDX NOASSERTION).
func UnknownString() OptString { return OptString{P: PresenceUnknown} }

// IsZero reports Absent (drives encoding/json omitzero).
func (o OptString) IsZero() bool { return o.P == PresenceAbsent }

// Value returns the value and whether it is Known.
func (o OptString) Value() (string, bool) { return o.V, o.P == PresenceKnown }

// MarshalJSON encodes Unknown as null and Known as the value.
func (o OptString) MarshalJSON() ([]byte, error) {
	if o.P != PresenceKnown {
		return nullJSON, nil
	}
	return json.Marshal(o.V)
}

// UnmarshalJSON decodes null as Unknown and a string as Known.
func (o *OptString) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, nullJSON) {
		*o = OptString{P: PresenceUnknown}
		return nil
	}
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*o = OptString{P: PresenceKnown, V: v}
	return nil
}

// OptInt64 is a tri-state int64.
type OptInt64 struct {
	P Presence
	V int64
}

// KnownInt64 returns a Known OptInt64.
func KnownInt64(v int64) OptInt64 { return OptInt64{P: PresenceKnown, V: v} }

// UnknownInt64 returns an Unknown OptInt64.
func UnknownInt64() OptInt64 { return OptInt64{P: PresenceUnknown} }

// IsZero reports Absent (drives encoding/json omitzero).
func (o OptInt64) IsZero() bool { return o.P == PresenceAbsent }

// Value returns the value and whether it is Known.
func (o OptInt64) Value() (int64, bool) { return o.V, o.P == PresenceKnown }

// MarshalJSON encodes Unknown as null and Known as the number.
func (o OptInt64) MarshalJSON() ([]byte, error) {
	if o.P != PresenceKnown {
		return nullJSON, nil
	}
	return json.Marshal(o.V)
}

// UnmarshalJSON decodes null as Unknown and a number as Known.
func (o *OptInt64) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, nullJSON) {
		*o = OptInt64{P: PresenceUnknown}
		return nil
	}
	var v int64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*o = OptInt64{P: PresenceKnown, V: v}
	return nil
}

// OptTime is a tri-state timestamp.
type OptTime struct {
	P Presence
	V time.Time
}

// KnownTime returns a Known OptTime.
func KnownTime(v time.Time) OptTime { return OptTime{P: PresenceKnown, V: v} }

// UnknownTime returns an Unknown OptTime.
func UnknownTime() OptTime { return OptTime{P: PresenceUnknown} }

// IsZero reports Absent (drives encoding/json omitzero).
func (o OptTime) IsZero() bool { return o.P == PresenceAbsent }

// Value returns the value and whether it is Known.
func (o OptTime) Value() (time.Time, bool) { return o.V, o.P == PresenceKnown }

// MarshalJSON encodes Unknown as null and Known as RFC 3339.
func (o OptTime) MarshalJSON() ([]byte, error) {
	if o.P != PresenceKnown {
		return nullJSON, nil
	}
	return json.Marshal(o.V)
}

// UnmarshalJSON decodes null as Unknown and an RFC 3339 string as Known.
func (o *OptTime) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, nullJSON) {
		*o = OptTime{P: PresenceUnknown}
		return nil
	}
	var v time.Time
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*o = OptTime{P: PresenceKnown, V: v}
	return nil
}

// TriState is a yes/no/unknown fact (SPDX PresenceType). The zero value is
// TriUnknown.
type TriState uint8

// The three states.
const (
	TriUnknown TriState = iota
	TriYes
	TriNo
)

// MarshalJSON encodes as "unknown", "yes", or "no".
func (t TriState) MarshalJSON() ([]byte, error) {
	switch t {
	case TriYes:
		return []byte(`"yes"`), nil
	case TriNo:
		return []byte(`"no"`), nil
	default:
		return []byte(`"unknown"`), nil
	}
}

// UnmarshalJSON decodes "yes", "no", or anything else as TriUnknown.
func (t *TriState) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("TriState: %w", err)
	}
	switch s {
	case "yes":
		*t = TriYes
	case "no":
		*t = TriNo
	default:
		*t = TriUnknown
	}
	return nil
}
