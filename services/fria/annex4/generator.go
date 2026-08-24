package annex4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Generator compiles Annex IV technical documentation from an AIBOM inventory.
type Generator struct{}

// NewGenerator constructs an Annex IV document generator.
func NewGenerator() *Generator {
	return &Generator{}
}

// GenerateTechnicalDoc synthesizes all 6 statutory sections for an EU High-Risk AI system.
func (g *Generator) GenerateTechnicalDoc(systemName, provider, version, intendedPurpose string, inv *airom.Inventory) AnnexIVDocument {
	sections := make(map[TechnicalDocSection]string)

	sections[Section1_GeneralDescription] = fmt.Sprintf("System: %s\nProvider: %s\nVersion: %s\nIntended Purpose: %s\nStatutory Basis: EU AI Act Article 11 & Annex IV", systemName, provider, version, intendedPurpose)

	compCount := 0
	modelDetails := "Components:"
	if inv != nil {
		compCount = len(inv.Components)
		for _, c := range inv.Components {
			modelDetails += fmt.Sprintf("\n- %s (Kind: %s, ID: %s)", c.Name, c.Kind, c.ID)
		}
	}
	sections[Section2_ComponentSpecifications] = fmt.Sprintf("Total Discovered Components: %d\n%s", compCount, modelDetails)

	sections[Section3_DevelopmentAndTraining] = "Development Pipeline: Continuous integration with AIROM AIBOM scanner.\nTraining Data Governance: Strict provenance tracking with SPDX 3.0 Dataset Profiles and PII scrubbing."
	sections[Section4_MonitoringAndControl] = "Operational Monitoring: Real-time telemetry via AIROM Runtime Gateway, circuit breakers, and Kirchenbauer cryptographic watermarking."
	sections[Section5_RiskManagementSystem] = "Risk Management: Automated compliance scans against EU AI Act, Colorado AI Act, NYC LL144, and OWASP Top 10 for LLM."
	sections[Section6_LifecycleModifications] = "Lifecycle Traceability: Immutable cryptographic hash-chain ledger with broken-chain and bit-drift detection."

	fingerprint := "0000000000000000"
	if inv != nil {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", systemName, len(inv.Components))))
		fingerprint = hex.EncodeToString(h[:8])
	}

	return AnnexIVDocument{
		DocumentID:        fmt.Sprintf("annex4-%s-%s", systemName, fingerprint),
		SystemName:        systemName,
		Provider:          provider,
		Version:           version,
		Sections:          sections,
		AIBOMFingerprint:  fingerprint,
		StatutoryCitation: "Regulation (EU) 2024/1689 (EU AI Act) Article 11 and Annex IV",
		GeneratedAt:       time.Now().UTC(),
	}
}
