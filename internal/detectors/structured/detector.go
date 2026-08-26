package structured

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Detector evaluates structured generation calls against strict type safety and schema compliance invariants.
type Detector struct {
	mu sync.RWMutex
}

// NewDetector constructs a new structured generation detector.
func NewDetector() *Detector {
	return &Detector{}
}

// EvaluateCall verifies whether a structured generation call has robust schema guarantees.
func (d *Detector) EvaluateCall(spec StructuredCallSpec) SchemaGuaranteeResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now().UTC()
	var violations []string

	// 1. Type validation check (must have Pydantic/Zod or equivalent schema validation)
	if !spec.HasTypeValidation {
		violations = append(violations, "HIGH: Structured output lacks formal type validation (Pydantic/Zod), allowing unvalidated hallucinated keys")
	}

	// 2. Grammar enforcement or validation retries
	if !spec.EnforcesGrammar && spec.MaxRetries <= 0 {
		violations = append(violations, "MEDIUM: Output lacks both regex grammar constrained sampling and automatic validation retries")
	}

	cleanID := sanitizeID(fmt.Sprintf("structured-%s-%s", spec.EngineType, spec.SchemaName))
	comp := airom.Component{
		ID:         airom.ID(cleanID),
		Kind:       airom.KindFramework,
		Name:       fmt.Sprintf("%s-Schema-%s", spec.EngineType, spec.SchemaName),
		Provider:   airom.KnownString(string(spec.EngineType)),
		Confidence: 0.90,
		PURL:       fmt.Sprintf("pkg:structured/%s/%s@1.0", strings.ToLower(string(spec.EngineType)), spec.SchemaName),
		Props: []airom.KV{
			{Name: "structured.engine", Value: string(spec.EngineType)},
			{Name: "structured.schema", Value: spec.SchemaName},
			{Name: "structured.type_validated", Value: fmt.Sprintf("%v", spec.HasTypeValidation)},
			{Name: "structured.grammar_enforced", Value: fmt.Sprintf("%v", spec.EnforcesGrammar)},
		},
	}

	return SchemaGuaranteeResult{
		EngineType:   spec.EngineType,
		SchemaName:   spec.SchemaName,
		IsGuaranteed: len(violations) == 0,
		Violations:   violations,
		Component:    &comp,
		EvaluatedAt:  now,
	}
}

func sanitizeID(raw string) string {
	h := sha256.Sum256([]byte(raw))
	short := hex.EncodeToString(h[:4])
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, strings.ToLower(raw))
	if len(clean) > 40 {
		clean = clean[:40]
	}
	return fmt.Sprintf("%s-%s", clean, short)
}
