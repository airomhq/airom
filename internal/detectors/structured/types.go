// Package structured detects structured generation and schema constraint engines
// including Instructor, Outlines, Guidance, BAML, and native JSON Schema modes.
package structured

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// EngineType specifies the structured generation library or grammar engine.
type EngineType string

const (
	EngineInstructor EngineType = "INSTRUCTOR"
	EngineOutlines   EngineType = "OUTLINES"
	EngineGuidance   EngineType = "GUIDANCE"
	EngineJSONSchema EngineType = "NATIVE_JSON_SCHEMA"
	EngineBAML       EngineType = "BAML"
)

// StructuredCallSpec models a discovered constrained generation call.
type StructuredCallSpec struct {
	EngineType        EngineType `json:"engineType"`
	SchemaName        string     `json:"schemaName"`        // e.g. "UserExtractionModel"
	HasTypeValidation bool       `json:"hasTypeValidation"` // Pydantic/Zod validator present
	EnforcesGrammar   bool       `json:"enforcesGrammar"`   // Context-free grammar / regex constrained sampling
	MaxRetries        int        `json:"maxRetries"`        // Auto-retry on validation failure
	SourceLocation    string     `json:"sourceLocation"`
}

// SchemaGuaranteeResult contains the evaluation verdict for structured outputs.
type SchemaGuaranteeResult struct {
	EngineType   EngineType       `json:"engineType"`
	SchemaName   string           `json:"schemaName"`
	IsGuaranteed bool             `json:"isGuaranteed"`
	Violations   []string         `json:"violations"`
	Component    *airom.Component `json:"component"`
	EvaluatedAt  time.Time        `json:"evaluatedAt"`
}
